#!/usr/bin/env python3
"""Issue #35 [A4] — Replication cost: latency, success, and messages/query vs s (Phase 6, (iii)).

Sweeps the replication factor s in {3, 5, 7} at the frozen N=32 emulation ceiling, 10 qps, and
reports what higher replication COSTS. Combines the emulation runs collected by
``experiments/run_a4.sh`` with the calibrated Phase-5 simulator re-run at the SAME point per s,
producing ``results/A4_replication.csv`` + ``results/fig_A4_replication.png``.

Three metrics per s (issue #35), both from the SAME sources A3 uses so the numbers are comparable:
  * messages per query — the headline cost, LINEAR in s. A round trip = req+resp = 2 messages;
    a query costs ``route + 1 + s`` round trips on a DHT hit and twice that on a fallback
    (``sim/scale_sim.ring_round_trips(outcome, hops, s)`` — the SAME model A3 applies, now passed
    the swept s). Reported as ring messages / queries-processed (a per-query average).
  * p50 (and p95/p99) latency — in EMULATION this rises with s because ``storage.get_chunk`` reads
    replicas SEQUENTIALLY; in the SIM it is ~flat because the model reads them in parallel (max
    RTT). That divergence is the interesting cross-check, flagged in ``results/A4_NOTES.md``.
  * success rate — at N=32 steady-state (no churn / no failures) this is ~flat across s; replication
    does not degrade correctness, and its AVAILABILITY benefit shows only under failure (Phase 6 A6
    / churn). A4 is the cost side; the success column is recorded for completeness.

The successor-list length is raised to max(3, s-1) on both sides so a replica set of s>4 can be
filled (emulation: run_ring_node's runtime SUCC_LIST_LEN override, chord.py untouched; sim:
``run_workload(succ_list_len=...)``). The s=3 point keeps the frozen default 3, so it reproduces
A1/A3's s=3 conditions — a built-in sanity check.

Run:  python3 experiments/a4_replication.py            # reads results/a4/ + runs sim, writes CSV+PNG
      python3 experiments/a4_replication.py --no-plot  # table only
      python3 experiments/a4_replication.py --sim-only  # skip emulation (fast, no Docker snapshots)
"""
from __future__ import annotations

import argparse
import csv
import math
import statistics
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
A4_DIR = RESULTS / "a4"
OUT_CSV = RESULTS / "A4_replication.csv"
OUT_FIG = RESULTS / "fig_A4_replication.png"

# import the simulator's message model + workload so emulation and sim use IDENTICAL accounting.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from sim.query_sim import DEFAULT_SEED, FALLBACK_STEPS, run_workload, summarize  # noqa: E402
from sim.scale_sim import ring_round_trips  # noqa: E402

# frozen A4 workload (PARAMETERS.md / run_a4.sh) — recorded per row for a self-contained deliverable
A4_N = 32
A4_QPS = 10.0
A4_DURATION_S = 30            # emulation measured window (run_a4.sh A4_DURATION)
SEED = DEFAULT_SEED
S_LEVELS = (3, 5, 7)          # the replication-factor sweep (issue #35)
SIM_DURATION_S = 60           # sim measured window (a rate/average is duration-normalised)
SIM_WARMUP_S = 30


def succ_list_len_for(s: int) -> int:
    """Successor-list length a replica set of s needs: [primary] + (s-1) successors; >= frozen 3."""
    return max(3, s - 1)


# ---- percentile / stats helpers — identical to experiments/a3_scalability.py ----
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


def load_client_rows(path: Path) -> list[dict]:
    """Parse a query_gen.py client CSV -> [{ts, latency, success}, ...]. Same schema as A1/A2/A3."""
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out.append({
                "ts": float(r["timestamp"]),
                "latency": float(r["latency_ms"]),
                "success": str(r["success"]).strip().lower() == "true",
            })
    return out


def load_node_rows(path: Path) -> list[tuple[str, int]]:
    """Parse a node-side queries.csv -> [(outcome, hops), ...]."""
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            try:
                out.append((str(r["outcome"]).strip(), int(r["hops"])))
            except (KeyError, ValueError):
                continue
    return out


def ring_messages_for(rows: list[tuple[str, int]], s: int) -> int:
    """Total ring messages for a set of (outcome, hops) rows, via the sim's model at replication s.

    round trip = request + response = 2 messages (scale_sim.ring_round_trips returns round trips).
    Guards a rare fallback log where hops < FALLBACK_STEPS (clamp the route component to 0).
    """
    total_rt = 0
    for outcome, hops in rows:
        if outcome == "fallback" and hops < FALLBACK_STEPS:
            hops = FALLBACK_STEPS
        total_rt += ring_round_trips(outcome, hops, s)
    return 2 * total_rt


# ---------------------------------------------------------------------------------------
# Emulation side: aggregate results/a4/s<s>/run<r>/{client.csv, ring/<j>_queries.csv}.
# ---------------------------------------------------------------------------------------
def emulation_row(s: int) -> dict | None:
    sdir = A4_DIR / f"s{s}"
    if not sdir.is_dir():
        return None
    runs = sorted(d for d in sdir.glob("run*") if d.is_dir())
    succ, p50s, p95s, p99s, mpq = [], [], [], [], []
    used = 0
    for run in runs:
        client = run / "client.csv"
        if not client.exists():
            continue
        crows = load_client_rows(client)
        if not crows:
            continue
        used += 1
        ok = [r for r in crows if r["success"]]
        succ.append(100.0 * len(ok) / len(crows))
        a, b, c = _pcts([r["latency"] for r in ok])
        p50s.append(a); p95s.append(b); p99s.append(c)
        # messages per query: total ring messages over ALL node logs / queries processed.
        nrows: list[tuple[str, int]] = []
        for logf in (run / "ring").glob("*_queries.csv"):
            nrows.extend(load_node_rows(logf))
        if nrows:
            mpq.append(ring_messages_for(nrows, s) / len(nrows))

    if used == 0:
        return None
    succ_m, succ_sd = _mean_sd(succ)
    p50_m, p50_sd = _mean_sd(p50s)
    p95_m, _ = _mean_sd(p95s)
    p99_m, _ = _mean_sd(p99s)
    mpq_m, mpq_sd = _mean_sd(mpq)
    return {
        "source": "emulation", "s": s, "succ_list_len": succ_list_len_for(s),
        "n": A4_N, "qps": A4_QPS, "duration_s": A4_DURATION_S, "runs": used,
        "success_rate_pct": succ_m, "success_sd": succ_sd,
        "p50_ms": p50_m, "p95_ms": p95_m, "p99_ms": p99_m, "p50_sd": p50_sd,
        "messages_per_query": mpq_m, "messages_per_query_sd": mpq_sd,
    }


# ---------------------------------------------------------------------------------------
# Simulation side: the calibrated query_sim at N=32, 10 qps, per s (sim has no loss -> success 100).
# ---------------------------------------------------------------------------------------
def sim_row(s: int, n: int = A4_N) -> dict:
    _sim, rows = run_workload(n=n, qps=A4_QPS, duration_s=SIM_DURATION_S, warmup_s=SIM_WARMUP_S,
                              seed=SEED, s=s, succ_list_len=succ_list_len_for(s))
    summ = summarize(rows)
    mpq = ring_messages_for([(r.outcome, r.hops) for r in rows], s) / len(rows) if rows else float("nan")
    return {
        "source": "sim", "s": s, "succ_list_len": succ_list_len_for(s),
        "n": n, "qps": A4_QPS, "duration_s": SIM_DURATION_S, "runs": 1,
        "success_rate_pct": 100.0, "success_sd": 0.0,
        "p50_ms": summ["p50_ms"], "p95_ms": summ["p95_ms"], "p99_ms": summ["p99_ms"], "p50_sd": 0.0,
        "messages_per_query": mpq, "messages_per_query_sd": 0.0,
    }


# ---------------------------------------------------------------------------------------
# CSV.
# ---------------------------------------------------------------------------------------
FIELDS = ["source", "s", "succ_list_len", "n", "qps", "duration_s", "runs",
          "success_rate_pct", "success_sd",
          "p50_ms", "p95_ms", "p99_ms", "p50_sd",
          "messages_per_query", "messages_per_query_sd"]


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
    def key(r):    # emulation first, then sim; by s within each
        return (0 if r["source"] == "emulation" else 1, r["s"])
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=key):
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# ---------------------------------------------------------------------------------------
# Plot: messages/query (linear in s) + p50 latency vs s, emulation + sim. Style mirrors A2/A3.
# ---------------------------------------------------------------------------------------
def make_plot(rows: list[dict]) -> None:
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

    emu = sorted([r for r in rows if r["source"] == "emulation"], key=lambda r: r["s"])
    sim = sorted([r for r in rows if r["source"] == "sim"], key=lambda r: r["s"])
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    # --- panel 1: messages per query vs s (the headline cost, ~linear in s) ---
    ax = axes[0]
    if emu:
        ax.errorbar([r["s"] for r in emu], [r["messages_per_query"] for r in emu],
                    yerr=[r["messages_per_query_sd"] for r in emu], marker="o", ms=6, lw=1.8,
                    capsize=3, color=EMU, label="emulation")
    if sim:
        ax.plot([r["s"] for r in sim], [r["messages_per_query"] for r in sim],
                marker="s", ms=6, lw=1.6, ls="--", color=SIM, label="simulation")
    ax.set_xlabel("replication factor s")
    ax.set_ylabel("ring messages per query")
    ax.set_title("Replication cost: messages/query vs s (N=32)")
    ax.set_xticks(S_LEVELS)
    ax.legend(frameon=False, fontsize=9)

    # --- panel 2: p50 latency vs s (emulation rises — sequential reads; sim ~flat — parallel) ---
    ax = axes[1]
    if emu:
        ax.errorbar([r["s"] for r in emu], [r["p50_ms"] for r in emu],
                    yerr=[r["p50_sd"] for r in emu], marker="o", ms=6, lw=1.8,
                    capsize=3, color=EMU, label="emulation p50")
    if sim:
        ax.plot([r["s"] for r in sim], [r["p50_ms"] for r in sim],
                marker="s", ms=6, lw=1.6, ls="--", color=SIM, label="simulation p50")
    ax.set_xlabel("replication factor s")
    ax.set_ylabel("p50 latency (ms)")
    ax.set_title("p50 latency vs s (N=32, 10 qps)")
    ax.set_xticks(S_LEVELS)
    ax.set_ylim(bottom=0)
    ax.legend(frameon=False, fontsize=9)

    fig.suptitle("A4 — replication cost: messages/query & latency vs s (emulation + simulation)",
                 y=1.02, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="A4 replication-cost analysis (issue #35).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--sim-only", action="store_true",
                    help="skip emulation snapshots (fast sim-only smoke, no Docker needed)")
    args = ap.parse_args()

    rows: list[dict] = []

    # --- emulation (s = 3/5/7) ---
    if not args.sim_only:
        print("== A4: emulation (results/a4/) ==")
        for s in S_LEVELS:
            r = emulation_row(s)
            if r is None:
                print(f"  [s={s}] no snapshots under {_rel(A4_DIR / f's{s}')} — skipped")
                continue
            rows.append(r)
            print(f"  [s={s}] runs={r['runs']} success={r['success_rate_pct']:5.1f}% "
                  f"p50={r['p50_ms']:.1f}ms msgs/query={r['messages_per_query']:.2f}")
        if not rows:
            print("  (no emulation snapshots found — run experiments/run_a4.sh, or use --sim-only)")

    # --- simulation: the same N=32 point per s (message-model cross-check; latency ~flat in s) ---
    print(f"\n== A4: simulation @ N={A4_N}, {A4_QPS:g} qps (calibrated query_sim, seed {SEED}) ==")
    for s in S_LEVELS:
        r = sim_row(s)
        rows.append(r)
        print(f"  [s={s}] (sll={r['succ_list_len']}) p50={r['p50_ms']:.1f} p95={r['p95_ms']:.1f} "
              f"p99={r['p99_ms']:.1f}ms msgs/query={r['messages_per_query']:.2f}")

    if not rows:
        print("error: nothing to write", file=sys.stderr)
        return 1

    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
