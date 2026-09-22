#!/usr/bin/env python3
"""Issue #34 [A3] — Scalability: throughput & per-node load vs N (Phase 6, examiner point (iii)).

Combines the emulation runs collected by ``experiments/run_a3.sh`` (N=4/8/16/32 at a fixed 50 qps,
the frozen emulation ceiling) with the calibrated Phase-5 simulator re-run at the SAME 50 qps for
the large-N points (N=1,000/5,000/10,000), producing one combined scalability curve:
``results/A3_scalability.csv`` + ``results/fig_A3_scalability.png``.

Two metrics vs N, both at a fixed offered load:
  * throughput / goodput — near-flat at ~50 qps below saturation (offered load held fixed);
    confirms scaling the ring does not cost throughput. From the client CSV (emulation) / the
    open-loop workload (sim).
  * per-node message load (msgs/node/s) — the headline scalability signal: it FALLS as N grows,
    because a fixed query load is spread over more nodes and each query still touches only
    O(log N) of them.

Per-node load — the one non-obvious mechanic (identical model both sides, so the points are
comparable). The simulator derives msgs/node/s from each query's routing outcome via
``sim/scale_sim.py``'s ``ring_round_trips(outcome, hops)`` (a round trip = req+resp = 2 messages).
The emulation node logs (``queries.csv``) record the same ``(outcome, hops)`` per query with the
same conventions (``node/query.py``: dht_hit hops = Chord route length; fallback hops = route + 3
iterative steps == the sim's ``hops - FALLBACK_STEPS``). So we IMPORT ``ring_round_trips`` and apply
it to the measured emulation rows — no re-derivation, no drift from the sim. It counts query-path
DHT/Chord RPCs only (excludes maintenance traffic), exactly as the sim does — flagged in
``results/A3_NOTES.md``.

Run:  python3 experiments/a3_scalability.py            # reads results/a3/ + runs sim, writes CSV+PNG
      python3 experiments/a3_scalability.py --no-plot  # table only
      python3 experiments/a3_scalability.py --sim-only  # skip emulation (fast, no Docker snapshots)
"""
from __future__ import annotations

import argparse
import csv
import math
import os
import statistics
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
A3_DIR = RESULTS / "a3"
OUT_CSV = RESULTS / "A3_scalability.csv"
OUT_FIG = RESULTS / "fig_A3_scalability.png"

# import the simulator's message model + workload so emulation and sim use the IDENTICAL accounting.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from sim.query_sim import DEFAULT_SEED, FALLBACK_STEPS, run_workload, summarize  # noqa: E402
from sim.scale_sim import ring_round_trips  # noqa: E402

# frozen A3 workload (PARAMETERS.md / run_a3.sh) — recorded per row for a self-contained deliverable
A3_QPS = 50.0
A3_DURATION_S = 30            # emulation measured window (run_a3.sh A3_DURATION)
A3_WARMUP_S = 30
SEED = DEFAULT_SEED
EMU_NS = (4, 8, 16, 32)       # emulation ceiling (PARAMETERS.md §1)
SIM_LARGE_NS = (1000, 5000, 10000)   # large-N scaling — the Phase-5 simulator carries these
SIM_DURATION_S = 60           # sim measured window (matches scale_sim; a rate is duration-normalised)
SIM_WARMUP_S = 30


# ---- percentile helpers — identical to experiments/a2_throughput.py ----
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
    """Parse a query_gen.py client CSV -> [{ts, latency, success}, ...]. Same schema as A1/A2."""
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


def ring_messages_for(rows: list[tuple[str, int]]) -> int:
    """Total ring messages for a set of (outcome, hops) rows, via the sim's model.

    round trip = request + response = 2 messages (scale_sim.ring_round_trips returns round trips).
    ``ring_round_trips`` does ``hops - FALLBACK_STEPS`` for fallback; guard against a rare log where
    that would go negative (clamp the route component to 0) so the count never underflows.
    """
    total_rt = 0
    for outcome, hops in rows:
        if outcome == "fallback" and hops < FALLBACK_STEPS:
            hops = FALLBACK_STEPS               # clamp route component to 0 (defensive)
        total_rt += ring_round_trips(outcome, hops)
    return 2 * total_rt


# ---------------------------------------------------------------------------------------
# Emulation side: aggregate results/a3/N<n>/run<r>/{client.csv, ring/<j>_queries.csv}.
# ---------------------------------------------------------------------------------------
def emulation_row(n: int) -> dict | None:
    ndir = A3_DIR / f"N{n}"
    if not ndir.is_dir():
        return None
    runs = sorted(d for d in ndir.glob("run*") if d.is_dir())
    thr, good, succ = [], [], []
    p50s, p95s, p99s, load = [], [], [], []
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
        ts = [r["ts"] for r in crows]
        span = (max(ts) - min(ts)) if len(ts) > 1 else 0.0
        thr.append(len(crows) / span if span > 0 else float("nan"))     # achieved send rate
        good.append(len(ok) / A3_DURATION_S)                            # goodput (successful qps)
        succ.append(100.0 * len(ok) / len(crows))
        a, b, c = _pcts([r["latency"] for r in ok])
        p50s.append(a); p95s.append(b); p99s.append(c)
        # per-node load: sum ring messages over ALL this run's node logs, / N / duration.
        nrows: list[tuple[str, int]] = []
        for logf in (run / "ring").glob("*_queries.csv"):
            nrows.extend(load_node_rows(logf))
        total_msgs = ring_messages_for(nrows)
        load.append(total_msgs / n / A3_DURATION_S)

    if used == 0:
        return None
    thr_m, thr_sd = _mean_sd(thr)
    good_m, _ = _mean_sd(good)
    succ_m, succ_sd = _mean_sd(succ)
    p50_m, _ = _mean_sd(p50s)
    p95_m, p95_sd = _mean_sd(p95s)
    p99_m, _ = _mean_sd(p99s)
    load_m, load_sd = _mean_sd(load)
    return {
        "source": "emulation", "n": n, "qps": A3_QPS, "duration_s": A3_DURATION_S, "runs": used,
        "throughput_qps": thr_m, "throughput_sd": thr_sd, "goodput_qps": good_m,
        "success_rate_pct": succ_m, "success_sd": succ_sd,
        "msgs_per_node_per_s": load_m, "msgs_per_node_sd": load_sd,
        "p50_ms": p50_m, "p95_ms": p95_m, "p99_ms": p99_m, "p95_sd": p95_sd,
    }


# ---------------------------------------------------------------------------------------
# Simulation side: run the calibrated query_sim at the SAME 50 qps (large N + a small-N overlay).
# ---------------------------------------------------------------------------------------
def sim_row(n: int) -> dict:
    _sim, rows = run_workload(n=n, qps=A3_QPS, duration_s=SIM_DURATION_S, warmup_s=SIM_WARMUP_S,
                              seed=SEED)
    s = summarize(rows)
    total_msgs = ring_messages_for([(r.outcome, r.hops) for r in rows])
    good = sum(1 for r in rows) / SIM_DURATION_S     # sim has no loss model -> goodput == offered
    return {
        "source": "sim", "n": n, "qps": A3_QPS, "duration_s": SIM_DURATION_S, "runs": 1,
        "throughput_qps": len(rows) / SIM_DURATION_S, "throughput_sd": 0.0, "goodput_qps": good,
        "success_rate_pct": 100.0, "success_sd": 0.0,
        "msgs_per_node_per_s": total_msgs / n / SIM_DURATION_S, "msgs_per_node_sd": 0.0,
        "p50_ms": s["p50_ms"], "p95_ms": s["p95_ms"], "p99_ms": s["p99_ms"], "p95_sd": 0.0,
    }


# ---------------------------------------------------------------------------------------
# CSV.
# ---------------------------------------------------------------------------------------
FIELDS = ["source", "n", "qps", "duration_s", "runs",
          "throughput_qps", "throughput_sd", "goodput_qps",
          "success_rate_pct", "success_sd",
          "msgs_per_node_per_s", "msgs_per_node_sd", "total_ring_messages",
          "p50_ms", "p95_ms", "p99_ms", "p95_sd"]


def _fmt(v) -> str:
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.4f}"
    return str(v)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def write_csv(rows: list[dict]) -> None:
    def key(r):    # emulation first, then sim; by N within each
        return (0 if r["source"] == "emulation" else 1, r["n"])
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=key):
            # recover total_ring_messages for the record (= msgs/node/s * N * duration)
            tot = int(round(r["msgs_per_node_per_s"] * r["n"] * r["duration_s"]))
            w.writerow({k: _fmt({**r, "total_ring_messages": tot}.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# ---------------------------------------------------------------------------------------
# Plot: per-node load + throughput vs N (log-x over N=4..10,000), emulation + sim.
# Style mirrors experiments/a2_throughput.py.
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

    emu = sorted([r for r in rows if r["source"] == "emulation"], key=lambda r: r["n"])
    sim = sorted([r for r in rows if r["source"] == "sim"], key=lambda r: r["n"])
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    # --- panel 1: per-node message load vs N (log-log) ---
    ax = axes[0]
    if emu:
        ax.errorbar([r["n"] for r in emu], [r["msgs_per_node_per_s"] for r in emu],
                    yerr=[r["msgs_per_node_sd"] for r in emu], marker="o", ms=5, lw=1.8,
                    capsize=3, color=EMU, label="emulation (N≤32)")
    if sim:
        ax.plot([r["n"] for r in sim], [r["msgs_per_node_per_s"] for r in sim],
                marker="s", ms=5, lw=1.6, ls="--", color=SIM, label="simulation")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("ring size N (nodes)")
    ax.set_ylabel("per-node message load (msgs/node/s)")
    ax.set_title("Per-node load vs N (fixed 50 qps)")
    ax.legend(frameon=False, fontsize=9)

    # --- panel 2: throughput / goodput vs N ---
    ax = axes[1]
    if emu:
        ax.errorbar([r["n"] for r in emu], [r["goodput_qps"] for r in emu],
                    yerr=[r["throughput_sd"] for r in emu], marker="o", ms=5, lw=1.8,
                    capsize=3, color=EMU, label="emulation goodput")
    if sim:
        ax.plot([r["n"] for r in sim], [r["throughput_qps"] for r in sim],
                marker="s", ms=5, lw=1.6, ls="--", color=SIM, label="simulation throughput")
    ax.axhline(A3_QPS, color=MUTED, ls=":", lw=1.2, label=f"offered {A3_QPS:g} qps")
    ax.set_xscale("log")
    ax.set_xlabel("ring size N (nodes)")
    ax.set_ylabel("throughput (qps)")
    ax.set_ylim(0, A3_QPS * 1.25)
    ax.set_title("Throughput vs N (fixed 50 qps)")
    ax.legend(frameon=False, fontsize=9)

    fig.suptitle("A3 — resolver scalability: per-node load & throughput vs N (emulation + simulation)",
                 y=1.02, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="A3 scalability analysis (issue #34).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--sim-only", action="store_true",
                    help="skip emulation snapshots (fast sim-only smoke, no Docker needed)")
    args = ap.parse_args()

    rows: list[dict] = []

    # --- emulation (N=4/8/16/32) ---
    if not args.sim_only:
        print("== A3: emulation (results/a3/) ==")
        for n in EMU_NS:
            r = emulation_row(n)
            if r is None:
                print(f"  [N={n:>3}] no snapshots under {_rel(A3_DIR / f'N{n}')} — skipped")
                continue
            rows.append(r)
            print(f"  [N={n:>3}] runs={r['runs']} goodput={r['goodput_qps']:5.1f}qps "
                  f"success={r['success_rate_pct']:5.1f}% "
                  f"load={r['msgs_per_node_per_s']:7.3f} msgs/node/s p50={r['p50_ms']:.1f}ms")
        if not rows:
            print(f"  (no emulation snapshots found — run experiments/run_a3.sh, "
                  f"or use --sim-only)")

    # --- simulation: small-N overlay (validation) + large N (the scaling evidence), all @ 50 qps ---
    print(f"\n== A3: simulation @ {A3_QPS:g} qps (calibrated query_sim, seed {SEED}) ==")
    sim_ns = list(EMU_NS) + list(SIM_LARGE_NS)   # small N overlaps emulation for a cross-check
    for n in sim_ns:
        r = sim_row(n)
        rows.append(r)
        tag = "overlay" if n in EMU_NS else "scale"
        print(f"  [N={n:>5}] ({tag}) throughput={r['throughput_qps']:5.1f}qps "
              f"load={r['msgs_per_node_per_s']:7.3f} msgs/node/s "
              f"p50={r['p50_ms']:.1f} p95={r['p95_ms']:.1f} p99={r['p99_ms']:.1f}ms")

    if not rows:
        print("error: nothing to write", file=sys.stderr)
        return 1

    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
