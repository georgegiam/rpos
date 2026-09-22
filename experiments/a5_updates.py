#!/usr/bin/env python3
"""Issue #36 [A5] — Update commit latency, messages/update, and ledger growth (Phase 6, (iii)).

Combines the emulation runs collected by ``experiments/run_a5.sh`` (50 real ledger updates driven
over the live N=32 ring by ``experiments/a5_driver.py``) with the purpose-built Phase-5 simulator
``sim/ledger_sim.py``, producing ``results/A5_updates.csv`` + ``results/fig_A5_updates.png``.

Three metrics (issue #36):
  * commit latency — p50/p95/p99 of ``propose_update`` measured on the proposer, over committed
    updates. In EMULATION this is real wall-clock over netem (5/50 ms two-tier). The sim is a
    MODEL only: the update path was never calibrated (``calibrate.py`` covers the read path), so
    the sim latency is the analytic lower/upper-bound band, not a fitted number — flagged in NOTES.
  * messages per update — COUNTED on the wire in emulation (socket_net.rpc_counter around the
    unchanged 2PC: find_successor hops + get_succ_list + ledger_precommit x s + ledger_commit x s;
    a round-trip = 2 messages). The sim reports 2 * round_trips. CAVEAT: the emulation count is
    WIRE round-trips (self-directed calls short-circuit before the socket), while the sim counts
    LOGICAL round-trips including proposer-self ones, so sim >= emu by the proposer's self-RPCs.
  * ledger growth — MEASURED ring-wide in emulation (sum of len(node.ledger) before/after; each
    committed update appends one hash-chain entry on each of the s replicas, so delta == committed
    x s). The sim's 2 h horizon (client updates + TTL-expiry refreshes) gives the growth-over-time
    curve a single 50-update run cannot show.

Run:  python3 experiments/a5_updates.py            # reads results/a5/ + runs sim, writes CSV+PNG
      python3 experiments/a5_updates.py --no-plot  # table only
      python3 experiments/a5_updates.py --sim-only  # skip emulation (fast, no Docker snapshots)
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
A5_DIR = RESULTS / "a5"
OUT_CSV = RESULTS / "A5_updates.csv"
OUT_FIG = RESULTS / "fig_A5_updates.png"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from sim.ledger_sim import DEFAULT_SEED, run_workload  # noqa: E402

# frozen A5 workload (PARAMETERS.md / run_a5.sh) — recorded per row for a self-contained deliverable
A5_N = 32
A5_S = 3                         # frozen replication factor
A5_UPDATES = 50
SEED = DEFAULT_SEED
# sim cross-check: the ledger sim's default long horizon so the 300–3600 s TTL ladder expires and
# the ledger-growth curve is meaningful (sim time is free). update_qps=1 matches its default.
SIM_UPDATE_QPS = 1.0
SIM_DURATION_S = 7200
SIM_WARMUP_S = 30


# ---- percentile / stats helpers — identical to experiments/a4_replication.py ----
def _percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * p
    lo = int(math.floor(k))
    hi = min(lo + 1, len(sorted_vals) - 1)
    if lo == hi:
        return sorted_vals[lo]
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def _pcts(latencies: list[float]) -> tuple[float, float, float]:
    s = sorted(latencies)
    return _percentile(s, 0.50), _percentile(s, 0.95), _percentile(s, 0.99)


def _mean_sd(vals: list[float]) -> tuple[float, float]:
    vals = [v for v in vals if not math.isnan(v)]
    if not vals:
        return float("nan"), 0.0
    m = statistics.fmean(vals)
    sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
    return m, sd


# ---------------------------------------------------------------------------------------
# Emulation side: aggregate results/a5/run<r>/{updates.csv, growth.json}.
# ---------------------------------------------------------------------------------------
def load_update_rows(path: Path) -> list[dict]:
    """Parse an a5_driver.py updates.csv -> [{seq, outcome, latency, round_trips, messages, ...}]."""
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            try:
                out.append({
                    "seq": int(r["seq"]),
                    "outcome": str(r["outcome"]).strip(),
                    "latency": float(r["latency_ms"]),
                    "round_trips": int(r["round_trips"]),
                    "messages": int(r["messages"]),
                    "entries": int(r["entries_appended"]),
                    "cum": int(r["ledger_len_cum"]),
                })
            except (KeyError, ValueError):
                continue
    return out


def emulation_row() -> tuple[dict | None, list[dict]]:
    """Aggregate the emulation runs. Returns (summary_row, per_update_rows_of_last_run_for_plot)."""
    if not A5_DIR.is_dir():
        return None, []
    runs = sorted(d for d in A5_DIR.glob("run*") if d.is_dir())
    committed, p50s, p95s, p99s, mpu, rtu, deltas, counts = [], [], [], [], [], [], [], []
    used = 0
    plot_rows: list[dict] = []
    for run in runs:
        upd = run / "updates.csv"
        if not upd.exists():
            continue
        rows = load_update_rows(upd)
        if not rows:
            continue
        used += 1
        counts.append(len(rows))
        ok = [r for r in rows if r["outcome"] == "committed"]
        committed.append(len(ok))
        a, b, c = _pcts([r["latency"] for r in ok])
        p50s.append(a); p95s.append(b); p99s.append(c)
        mpu.append(statistics.fmean([r["messages"] for r in ok]) if ok else float("nan"))
        rtu.append(statistics.fmean([r["round_trips"] for r in ok]) if ok else float("nan"))
        gpath = run / "growth.json"
        if gpath.exists():
            deltas.append(int(json.loads(gpath.read_text()).get("ring_ledger_delta", 0)))
        plot_rows = rows                       # keep the last run's per-update curve for the figure

    if used == 0:
        return None, []
    committed_m, committed_sd = _mean_sd([float(x) for x in committed])
    p50_m, p50_sd = _mean_sd(p50s)
    p95_m, _ = _mean_sd(p95s)
    p99_m, _ = _mean_sd(p99s)
    mpu_m, mpu_sd = _mean_sd(mpu)
    rtu_m, _ = _mean_sd(rtu)
    delta_m, _ = _mean_sd([float(x) for x in deltas]) if deltas else (float("nan"), 0.0)
    return {
        "source": "emulation", "n": A5_N, "s": A5_S,
        "updates_measured": max(counts) if counts else A5_UPDATES, "runs": used,
        "committed_mean": committed_m, "committed_sd": committed_sd,
        "p50_ms": p50_m, "p95_ms": p95_m, "p99_ms": p99_m, "p50_sd": p50_sd,
        "messages_per_update": mpu_m, "messages_per_update_sd": mpu_sd,
        "round_trips_per_update": rtu_m,
        "ledger_entries_appended": delta_m,
        "note": "wire RPCs; ledger delta measured ring-wide",
    }, plot_rows


# ---------------------------------------------------------------------------------------
# Simulation side: sim/ledger_sim.py at N=32 (client-update rows are the latency/messages
# cross-check; the full 2 h run — updates + TTL refreshes — gives the ledger-growth curve).
# ---------------------------------------------------------------------------------------
def sim_rows() -> tuple[dict, list]:
    _sim, rows = run_workload(n=A5_N, update_qps=SIM_UPDATE_QPS, duration_s=SIM_DURATION_S,
                              warmup_s=SIM_WARMUP_S, seed=SEED)
    updates = [r for r in rows if r.action == "update"]
    committed = [r for r in updates if r.outcome == "committed"]
    lat = sorted(r.latency_ms for r in committed) if committed else []
    entries_total = sum(r.entries_appended for r in rows)
    row = {
        "source": "sim", "n": A5_N, "s": A5_S, "updates_measured": len(updates), "runs": 1,
        "committed_mean": float(len(committed)), "committed_sd": 0.0,
        "p50_ms": _percentile(lat, 0.50), "p95_ms": _percentile(lat, 0.95),
        "p99_ms": _percentile(lat, 0.99), "p50_sd": 0.0,
        "messages_per_update": statistics.fmean([r.messages for r in committed]) if committed else float("nan"),
        "messages_per_update_sd": 0.0,
        "round_trips_per_update": statistics.fmean([r.round_trips for r in committed]) if committed else float("nan"),
        "ledger_entries_appended": float(entries_total),
        "note": f"logical RTs incl self; growth over {SIM_DURATION_S}s (updates+TTL refresh)",
    }
    return row, rows


# ---------------------------------------------------------------------------------------
# CSV.
# ---------------------------------------------------------------------------------------
FIELDS = ["source", "n", "s", "updates_measured", "runs",
          "committed_mean", "committed_sd",
          "p50_ms", "p95_ms", "p99_ms", "p50_sd",
          "messages_per_update", "messages_per_update_sd", "round_trips_per_update",
          "ledger_entries_appended", "note"]


def _fmt(v) -> str:
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.4f}"
    return str(v)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def write_csv(rows: list[dict]) -> None:
    def key(r):    # emulation first, then sim
        return 0 if r["source"] == "emulation" else 1
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=key):
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# ---------------------------------------------------------------------------------------
# Plot: (1) commit-latency percentiles emu-vs-sim; (2) ledger growth — measured 50-update curve
# + the sim's 2 h growth-over-time curve. Style mirrors A2/A3/A4.
# ---------------------------------------------------------------------------------------
def make_plot(emu: dict | None, emu_curve: list[dict], sim: dict, sim_rows_all: list) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    EMU, SIM = "#2a78d6", "#8a1c5a"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    # --- panel 1: commit-latency percentiles, emulation vs sim ---
    ax = axes[0]
    labels = ["p50", "p95", "p99"]
    x = range(len(labels))
    width = 0.38
    if emu:
        ax.bar([i - width / 2 for i in x], [emu["p50_ms"], emu["p95_ms"], emu["p99_ms"]],
               width, color=EMU, label="emulation (measured)")
    ax.bar([i + width / 2 for i in x], [sim["p50_ms"], sim["p95_ms"], sim["p99_ms"]],
           width, color=SIM, label="simulation (model)")
    ax.set_xticks(list(x)); ax.set_xticklabels(labels)
    ax.set_ylabel("commit latency (ms)")
    ax.set_title(f"Commit latency (N={A5_N}, s={A5_S})")
    ax.set_ylim(bottom=0)
    ax.legend(frameon=False, fontsize=9)

    # --- panel 2: ledger growth. Measured 50-update cumulative + sim 2 h curve (twin axis). ---
    ax = axes[1]
    if emu_curve:
        ax.plot([r["seq"] + 1 for r in emu_curve], [r["cum"] for r in emu_curve],
                marker="o", ms=4, lw=1.8, color=EMU, label="emulation (50 updates)")
    ax.set_xlabel("update index")
    ax.set_ylabel("ledger entries appended (ring-wide)", color=EMU)
    ax.tick_params(axis="y", labelcolor=EMU)
    ax.set_title("Ledger growth")
    ax.set_ylim(bottom=0)

    ax2 = ax.twiny()
    tmin = [(r.sim_time_ms / 1000.0, r.ledger_len) for r in sim_rows_all]
    if tmin:
        ax2.plot([t for t, _ in tmin], [n for _, n in tmin], lw=1.6, ls="--", color=SIM,
                 label="simulation (2 h)")
        ax2.set_xlabel("simulation time (s)", color=SIM)
        ax2.tick_params(axis="x", labelcolor=SIM)
    lines = ax.get_lines() + ax2.get_lines()
    ax.legend(lines, [ln.get_label() for ln in lines], frameon=False, fontsize=9, loc="upper left")

    fig.suptitle("A5 — update commit latency & ledger growth (emulation + simulation)",
                 y=1.03, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="A5 update-cost analysis (issue #36).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--sim-only", action="store_true",
                    help="skip emulation snapshots (fast sim-only smoke, no Docker needed)")
    args = ap.parse_args()

    rows: list[dict] = []
    emu = None
    emu_curve: list[dict] = []

    if not args.sim_only:
        print("== A5: emulation (results/a5/) ==")
        emu, emu_curve = emulation_row()
        if emu is None:
            print(f"  (no emulation snapshots under {_rel(A5_DIR)} — run experiments/run_a5.sh, "
                  f"or use --sim-only)")
        else:
            rows.append(emu)
            print(f"  runs={emu['runs']} committed={emu['committed_mean']:.1f}/{A5_UPDATES} "
                  f"p50={emu['p50_ms']:.1f}ms msgs/update={emu['messages_per_update']:.2f} "
                  f"ring-wide entries delta={emu['ledger_entries_appended']:.0f}")

    print(f"\n== A5: simulation @ N={A5_N}, s={A5_S} (sim/ledger_sim, seed {SEED}, "
          f"{SIM_DURATION_S}s horizon) ==")
    sim, sim_rows_all = sim_rows()
    rows.append(sim)
    print(f"  update rows={sim['updates_measured']} p50={sim['p50_ms']:.1f} p95={sim['p95_ms']:.1f} "
          f"p99={sim['p99_ms']:.1f}ms msgs/update={sim['messages_per_update']:.2f} "
          f"total entries={sim['ledger_entries_appended']:.0f}")

    if not rows:
        print("error: nothing to write", file=sys.stderr)
        return 1

    write_csv(rows)
    if not args.no_plot:
        make_plot(emu, emu_curve, sim, sim_rows_all)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
