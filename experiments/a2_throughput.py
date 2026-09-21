#!/usr/bin/env python3
"""Issue #33 [A2] — Throughput / saturation: analysis, table, and plot (Phase 6, examiner point (iii)).

Reads the per-level snapshots collected by ``experiments/run_a2.sh`` under ``results/a2/``, computes
success rate + achieved qps + p50/p95/p99 latency at each offered load level (aggregated over the 3
sweeps with run-to-run spread), locates the saturation point (first offered qps with mean success
< 95%), writes ``results/A2_throughput.csv``, overlays the frozen Unbound baseline throughput curve
(``results/baseline_unbound.csv``), and renders ``results/fig_A2_throughput.png``.

Why only the client CSV (unlike A1)
-----------------------------------
A2 is a throughput/saturation experiment: its metrics are success rate and latency percentiles vs
offered load. Both come straight from the client-side ``query_gen.py`` CSV
(``timestamp,domain,resolver_used,latency_ms,success``); no cache/dht/fallback split — and hence no
client<->node join — is needed here (that was A1's concern). So this reuses A1's parsing/percentile
helpers but skips the join entirely.

The generator-cap diagnostic (CLAUDE.md "flag, don't hide"): ``query_gen.py`` is open-loop but
bounded by its worker pool. run_a2.sh sizes --max-workers per level so the ring saturates first, but
we still report ``achieved_qps = rows/duration`` alongside the offered rate. If achieved << offered
while success stays high, the generator (not the ring) capped that level; if success falls < 95%,
that is genuine ring saturation. Both are visible in the CSV and the plot.

Run:  python3 experiments/a2_throughput.py            # reads results/a2/, writes CSV + PNG
      python3 experiments/a2_throughput.py --no-plot  # table only
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
A2_DIR = RESULTS / "a2"
OUT_CSV = RESULTS / "A2_throughput.csv"
OUT_FIG = RESULTS / "fig_A2_throughput.png"
UNBOUND_CSV = RESULTS / "baseline_unbound.csv"

DURATION_S = 30.0            # frozen configured measured window per level (run_a2.sh A2_DURATION),
                             # recorded as metadata; achieved throughput is derived from send spans
SAT_THRESHOLD = 95.0         # success-rate % below which a level is "saturated" (issue #33)


# ---- percentile — linear-interpolated, identical to experiments/a1_latency_vs_n.py ----
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
    """Parse a query_gen.py client CSV -> [{ts, latency, success}, ...]. Same schema as A1."""
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out.append({
                "ts": float(r["timestamp"]),
                "latency": float(r["latency_ms"]),
                "success": str(r["success"]).strip().lower() == "true",
            })
    return out


# ---------------------------------------------------------------------------------------
# Per-level, per-sweep summary, then aggregate across sweeps.
# ---------------------------------------------------------------------------------------
class LevelStat:
    """Aggregated stats for one offered-qps level across all sweeps."""

    def __init__(self, qps: int) -> None:
        self.qps = qps
        self.sweeps = 0
        self.rows = 0                       # summed over sweeps
        self.ok = 0
        self.run_success: list[float] = []  # per-sweep success %
        self.run_achieved: list[float] = [] # per-sweep achieved qps
        self.run_p50: list[float] = []
        self.run_p95: list[float] = []
        self.run_p99: list[float] = []

    def add_sweep(self, rows: list[dict]) -> None:
        if not rows:
            return
        self.sweeps += 1
        succ = [r for r in rows if r["success"]]
        self.rows += len(rows)
        self.ok += len(succ)
        self.run_success.append(100.0 * len(succ) / len(rows))
        # achieved (send) throughput = rows / actual send span. The generator submits exactly
        # qps×duration rows, so rows/duration is tautologically the offered rate; the real
        # diagnostic is the SPAN of send timestamps, which stretches past the measured window
        # only when the worker pool can't keep the offered schedule (a generator cap). Guard the
        # degenerate 1-row span with the configured window.
        ts = [r["ts"] for r in rows]
        span = (max(ts) - min(ts)) if len(ts) > 1 else 0.0
        self.run_achieved.append(len(rows) / span if span > 0 else float("nan"))
        p50, p95, p99 = _pcts([r["latency"] for r in succ])
        self.run_p50.append(p50)
        self.run_p95.append(p95)
        self.run_p99.append(p99)

    def summary(self) -> dict:
        succ_m, succ_sd = _mean_sd(self.run_success)
        ach_m, _ = _mean_sd(self.run_achieved)
        p50_m, _ = _mean_sd(self.run_p50)
        p95_m, p95_sd = _mean_sd(self.run_p95)
        p99_m, _ = _mean_sd(self.run_p99)
        return {
            "offered_qps": self.qps, "achieved_qps": ach_m, "sweeps": self.sweeps,
            "rows": self.rows, "ok": self.ok,
            "success_rate_pct": succ_m, "success_sd": succ_sd,
            "p50_ms": p50_m, "p95_ms": p95_m, "p99_ms": p99_m, "p95_sd": p95_sd,
        }


def discover_levels() -> list[int]:
    qs: set[int] = set()
    if A2_DIR.is_dir():
        for sweep in A2_DIR.glob("sweep*"):
            if not sweep.is_dir():
                continue
            for qdir in sweep.glob("q*"):
                if qdir.is_dir() and qdir.name[1:].isdigit():
                    qs.add(int(qdir.name[1:]))
    return sorted(qs)


def collect() -> list[dict]:
    levels = discover_levels()
    if not levels:
        return []
    sweeps = sorted([d for d in A2_DIR.glob("sweep*") if d.is_dir()])
    stats: list[dict] = []
    for q in levels:
        ls = LevelStat(q)
        for sweep in sweeps:
            client = sweep / f"q{q}" / "client.csv"
            if client.exists():
                ls.add_sweep(load_client_rows(client))
        if ls.sweeps:
            s = ls.summary()
            print(f"  [q={q:>3}] sweeps={ls.sweeps} rows={ls.rows} "
                  f"success={s['success_rate_pct']:5.1f}% (sd {s['success_sd']:.1f}) "
                  f"achieved={s['achieved_qps']:6.1f}qps p95={s['p95_ms']:7.1f}ms")
            stats.append(s)
    return stats


def mark_saturation(stats: list[dict]) -> int | None:
    """Return the lowest offered_qps whose mean success < 95% (the saturation point), or None."""
    sat = None
    for s in sorted(stats, key=lambda x: x["offered_qps"]):
        below = s["success_rate_pct"] < SAT_THRESHOLD
        s["saturated"] = below
        if below and sat is None:
            sat = s["offered_qps"]
    return sat


# ---------------------------------------------------------------------------------------
# Unbound baseline overlay (already a per-qps throughput sweep).
# ---------------------------------------------------------------------------------------
def load_unbound() -> list[dict]:
    if not UNBOUND_CSV.exists():
        return []
    out = []
    with open(UNBOUND_CSV, newline="") as f:
        for r in csv.DictReader(f):
            out.append({
                "offered_qps": float(r["offered_qps"]),
                "success_rate_pct": float(r["success_rate_pct"]),
                "p95_ms": float(r["p95_ms"]),
            })
    return sorted(out, key=lambda x: x["offered_qps"])


# ---------------------------------------------------------------------------------------
# CSV.
# ---------------------------------------------------------------------------------------
FIELDS = ["offered_qps", "achieved_qps", "duration_s", "warmup_s", "nodes", "seed", "netem",
          "sweeps", "rows", "ok", "success_rate_pct", "success_sd",
          "p50_ms", "p95_ms", "p99_ms", "p95_sd", "saturated"]

# frozen run metadata (PARAMETERS.md / run_a2.sh defaults) — recorded per row for a self-contained
# deliverable, matching the baseline_unbound.csv style.
META = {"duration_s": int(DURATION_S), "warmup_s": 30, "nodes": 32, "seed": 20260919, "netem": "on"}


def _fmt(v) -> str:
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.3f}"
    return str(v)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def write_csv(stats: list[dict]) -> None:
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for s in sorted(stats, key=lambda x: x["offered_qps"]):
            row = {**META, **s}
            w.writerow({k: _fmt(row.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(stats)} levels)")


# ---------------------------------------------------------------------------------------
# Plot: success rate + p95 latency vs offered qps, with the saturation crossing marked and the
# Unbound baseline overlaid. Style mirrors experiments/a1_latency_vs_n.py.
# ---------------------------------------------------------------------------------------
def make_plot(stats: list[dict], unbound: list[dict], sat_qps: int | None) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    RPOS, UNB, SAT = "#2a78d6", "#8a1c5a", "#eb6834"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })

    st = sorted(stats, key=lambda x: x["offered_qps"])
    xs = [s["offered_qps"] for s in st]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    # --- panel 1: success rate vs offered qps ---
    ax = axes[0]
    ys = [s["success_rate_pct"] for s in st]
    es = [s["success_sd"] for s in st]
    ax.errorbar(xs, ys, yerr=es, marker="o", ms=5, lw=1.8, capsize=3, color=RPOS, label="rpos ring")
    if unbound:
        ax.plot([u["offered_qps"] for u in unbound], [u["success_rate_pct"] for u in unbound],
                marker="s", ms=4, lw=1.4, ls="--", color=UNB, label="Unbound")
    ax.axhline(SAT_THRESHOLD, color=SAT, ls=":", lw=1.4, label=f"{SAT_THRESHOLD:.0f}% threshold")
    if sat_qps is not None:
        ax.axvline(sat_qps, color=SAT, ls="-", lw=1.2, alpha=0.6)
        # point at the saturated level in open space below the curve (avoids the 100% cluster)
        sat_row = next((s for s in st if s["offered_qps"] == sat_qps), None)
        sat_y = sat_row["success_rate_pct"] if sat_row else SAT_THRESHOLD
        ax.annotate(f"saturation ≈ {sat_qps} qps", xy=(sat_qps, sat_y), xytext=(sat_qps + 12, 45),
                    textcoords="data", color=SAT, fontsize=9,
                    arrowprops=dict(arrowstyle="->", color=SAT, lw=1.1))
    ax.set_xlabel("offered load (qps)")
    ax.set_ylabel("success rate (%)")
    ax.set_ylim(0, 103)
    ax.set_title("Success rate vs offered load")
    ax.legend(frameon=False, fontsize=9)

    # --- panel 2: p95 latency vs offered qps ---
    ax = axes[1]
    ys = [s["p95_ms"] for s in st]
    es = [s["p95_sd"] for s in st]
    ax.errorbar(xs, ys, yerr=es, marker="o", ms=5, lw=1.8, capsize=3, color=RPOS, label="rpos ring")
    if unbound:
        ax.plot([u["offered_qps"] for u in unbound], [u["p95_ms"] for u in unbound],
                marker="s", ms=4, lw=1.4, ls="--", color=UNB, label="Unbound")
    if sat_qps is not None:
        ax.axvline(sat_qps, color=SAT, ls="-", lw=1.2, alpha=0.6)
    ax.set_xlabel("offered load (qps)")
    ax.set_ylabel("p95 latency (ms)")
    ax.set_yscale("log")
    ax.set_title("p95 latency vs offered load")
    ax.legend(frameon=False, fontsize=9)

    fig.suptitle("A2 — resolver throughput / saturation at N=32 (vs Unbound baseline)",
                 y=1.02, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="A2 throughput / saturation analysis (issue #33).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    args = ap.parse_args()

    if not A2_DIR.is_dir():
        print(f"error: {A2_DIR} not found — run experiments/run_a2.sh first", file=sys.stderr)
        return 1

    print("== A2 analysis: throughput / saturation at N=32 ==")
    stats = collect()
    if not stats:
        print(f"error: no sweep*/q*/client.csv snapshots under {A2_DIR} — run run_a2.sh first",
              file=sys.stderr)
        return 1

    sat_qps = mark_saturation(stats)
    if sat_qps is not None:
        print(f"\nsaturation point (first level < {SAT_THRESHOLD:.0f}% success): {sat_qps} qps")
    else:
        print(f"\nno saturation within the tested levels (all ≥ {SAT_THRESHOLD:.0f}% success)")

    write_csv(stats)

    if not args.no_plot:
        make_plot(stats, load_unbound(), sat_qps)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
