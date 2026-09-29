#!/usr/bin/env python3
"""Issue #33 [A2] — Throughput / saturation, CACHE-CONTROLLED analysis (Phase 6, point (iii)).

Reads the cache-controlled snapshots collected by ``experiments/run_a2.sh`` under
``results/a2/<curve>/sweep*/q*/`` (curve in {cold, steady}) and produces TWO clean throughput
curves at N=32, replacing the old ascending sweep that confounded load with cache warming:

  * COLD-PATH  — UPSTREAM_TTL=0: the cache never retains, so every query is a DHT read. The
    conservative (DHT-work) saturation.
  * STEADY     — UPSTREAM_TTL huge + full pre-warm: every query is served from a warm cache. The
    cache-assisted throughput ceiling.

For each curve it reports, per offered-qps level (aggregated over sweeps): success rate + sd,
achieved qps (from the send-timestamp span — the generator-cap check), p50/p95/p99 of successful
queries, and the node-0 outcome mix (cache_hit / dht_hit / fallback) that PROVES the path
(COLD ~ all dht_hit, STEADY ~ all cache_hit). It then:
  * locates the saturation point = first level whose mean success < 95% (issue #33's criterion);
  * checks p95 is MONOTONICALLY NON-DECREASING with load (the methodology fix — if p95 still falls
    the cache control failed; this is flagged loudly, not hidden).

Writes ``results/A2_throughput.csv`` (single provenance — old mixed data removed by the collector)
and ``results/fig_A2_throughput.png`` (both curves).

Run:  python3 experiments/a2_throughput.py [--no-plot]
"""
from __future__ import annotations

import argparse
import csv
import math
import statistics
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
A2_DIR = RESULTS / "a2"
OUT_CSV = RESULTS / "A2_throughput.csv"
OUT_FIG = RESULTS / "fig_A2_throughput.png"

CURVES = ("cold", "steady")
SAT_THRESHOLD = 95.0    # success-rate % below which a level is "saturated" (issue #33)
MONO_REL_TOL = 0.90     # p95[i+1] >= 0.90*p95[i] is non-decreasing (10% relative noise band)
MONO_ABS_TOL = 5.0      # ...and only count a dip larger than 5 ms (ignore sub-ms cache-floor jitter)
N = 32


# ---- stats helpers ----
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
    return m, (statistics.stdev(vals) if len(vals) > 1 else 0.0)


def load_client_rows(path: Path) -> list[dict]:
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out.append({"ts": float(r["timestamp"]), "latency": float(r["latency_ms"]),
                        "success": str(r["success"]).strip().lower() == "true"})
    return out


def load_node_outcomes(level_dir: Path) -> dict[str, int]:
    """Pool node-side outcomes over ALL nodes' logs for a level (cold = distributed entry, so every
    node logs; steady = funnel, only node 0 logs). Proves the path: cold ~ all dht_hit, steady ~ all
    cache_hit, both ~ no fallback (DHT fully pre-warmed)."""
    counts = {"cache_hit": 0, "dht_hit": 0, "fallback": 0}
    ring_dir = level_dir / "ring"
    if not ring_dir.is_dir():
        return counts
    for p in sorted(ring_dir.glob("*_queries.csv")):
        with open(p, newline="") as f:
            for r in csv.DictReader(f):
                o = str(r["outcome"]).strip()
                if o in counts:
                    counts[o] += 1
    return counts


def achieved_qps(rows: list[dict]) -> float:
    """Offered rate actually realised = (n-1)/send-span. If << offered while success high, the
    generator (not the ring) capped this level; if success < 95%, it is genuine saturation."""
    if len(rows) < 2:
        return float("nan")
    ts = sorted(r["ts"] for r in rows)
    span = ts[-1] - ts[0]
    return (len(rows) - 1) / span if span > 0 else float("nan")


# ---- per-(curve, level) aggregation over sweeps ----
class Level:
    def __init__(self, qps: int) -> None:
        self.qps = qps
        self.sweeps = 0
        self.rows = self.ok = 0
        self.run_success: list[float] = []
        self.run_achieved: list[float] = []
        self.run_p50: list[float] = []
        self.run_p95: list[float] = []
        self.run_p99: list[float] = []
        self.outcomes = {"cache_hit": 0, "dht_hit": 0, "fallback": 0}

    def add_sweep(self, client: list[dict], node0: dict[str, int]) -> None:
        if not client:
            return
        self.sweeps += 1
        self.rows += len(client)
        succ = [r for r in client if r["success"]]
        self.ok += len(succ)
        self.run_success.append(100.0 * len(succ) / len(client))
        self.run_achieved.append(achieved_qps(client))
        p50, p95, p99 = _pcts([r["latency"] for r in succ])
        self.run_p50.append(p50); self.run_p95.append(p95); self.run_p99.append(p99)
        for k in self.outcomes:
            self.outcomes[k] += node0.get(k, 0)

    def row(self, curve: str) -> dict:
        succ_m, succ_sd = _mean_sd(self.run_success)
        ach_m, _ = _mean_sd(self.run_achieved)
        p50_m, _ = _mean_sd(self.run_p50)
        p95_m, p95_sd = _mean_sd(self.run_p95)
        p99_m, _ = _mean_sd(self.run_p99)
        tot = sum(self.outcomes.values()) or 1
        return {
            "curve": curve, "offered_qps": self.qps, "achieved_qps": ach_m,
            "nodes": N, "duration_s": 30, "sweeps": self.sweeps, "rows": self.rows, "ok": self.ok,
            "success_rate_pct": succ_m, "success_sd": succ_sd,
            "p50_ms": p50_m, "p95_ms": p95_m, "p99_ms": p99_m, "p95_sd": p95_sd,
            "cache_hit_pct": 100.0 * self.outcomes["cache_hit"] / tot,
            "dht_hit_pct": 100.0 * self.outcomes["dht_hit"] / tot,
            "fallback_pct": 100.0 * self.outcomes["fallback"] / tot,
        }


def discover_levels(curve_dir: Path) -> list[int]:
    qs: set[int] = set()
    for sweep in curve_dir.glob("sweep*"):
        for qdir in sweep.glob("q*"):
            if qdir.is_dir():
                try:
                    qs.add(int(qdir.name[1:]))
                except ValueError:
                    pass
    return sorted(qs)


def analyse_curve(curve: str) -> list[dict]:
    cdir = A2_DIR / curve
    if not cdir.is_dir():
        return []
    levels = discover_levels(cdir)
    sweeps = sorted(d for d in cdir.glob("sweep*") if d.is_dir())
    rows = []
    print(f"\n== A2 curve '{curve}' (N={N}) ==")
    for q in levels:
        lv = Level(q)
        for sweep in sweeps:
            client_csv = sweep / f"q{q}" / "client.csv"
            if client_csv.exists():
                lv.add_sweep(load_client_rows(client_csv),
                             load_node_outcomes(sweep / f"q{q}"))
        if lv.sweeps:
            r = lv.row(curve)
            rows.append(r)
            print(f"  [q={q:>3}] sweeps={lv.sweeps} success={r['success_rate_pct']:5.1f}% "
                  f"(sd {r['success_sd']:.1f}) achieved={r['achieved_qps']:6.1f} "
                  f"p95={r['p95_ms']:7.1f}ms  "
                  f"[cache {r['cache_hit_pct']:.0f}% / dht {r['dht_hit_pct']:.0f}% / "
                  f"fb {r['fallback_pct']:.0f}%]")
    return rows


def saturation_qps(rows: list[dict]) -> int | None:
    for r in sorted(rows, key=lambda x: x["offered_qps"]):
        if r["success_rate_pct"] < SAT_THRESHOLD:
            return r["offered_qps"]
    return None


def p95_monotonic(rows: list[dict]) -> tuple[bool, list[tuple[int, float]]]:
    """Is p95 monotonically non-decreasing with load over the NON-saturated region?

    The cache-warming confound (the bug this redo fixes) shows as p95 FALLING while success is still
    high — i.e. in the non-saturated region. So we check monotonicity only over levels with mean
    success >= 95% (once saturated, p95-of-*successful* can legitimately fall by survivor bias as slow
    queries time out and drop from the success set — a different, expected effect). A dip counts as a
    violation only if it is both >10% relative AND >5 ms absolute (so sub-ms cache-floor jitter on the
    steady curve does not trip it). Returns (ok, [(qps, p95)...]) over the checked region."""
    checked = [r for r in sorted(rows, key=lambda x: x["offered_qps"])
               if r["success_rate_pct"] >= SAT_THRESHOLD]
    seq = [(r["offered_qps"], r["p95_ms"]) for r in checked]
    ok = True
    for (_, prev), (_, cur) in zip(seq, seq[1:]):
        if math.isnan(prev) or math.isnan(cur):
            continue
        if cur < MONO_REL_TOL * prev and (prev - cur) > MONO_ABS_TOL:
            ok = False
    return ok, seq


def cache_state_constant(rows: list[dict]) -> tuple[float, float]:
    """The real confound test: does the per-level cache path stay CONSTANT across load? Returns
    (stdev of cache_hit_pct, stdev of dht_hit_pct) across levels. Near-zero => cache state is pinned
    (cold: dht every level; steady: cache every level), so no accumulation-with-load can bias p95."""
    ch = [r["cache_hit_pct"] for r in rows if not math.isnan(r["cache_hit_pct"])]
    dh = [r["dht_hit_pct"] for r in rows if not math.isnan(r["dht_hit_pct"])]
    ch_sd = statistics.stdev(ch) if len(ch) > 1 else 0.0
    dh_sd = statistics.stdev(dh) if len(dh) > 1 else 0.0
    return ch_sd, dh_sd


# ---- CSV ----
FIELDS = ["curve", "offered_qps", "achieved_qps", "nodes", "duration_s", "sweeps", "rows", "ok",
          "success_rate_pct", "success_sd", "p50_ms", "p95_ms", "p99_ms", "p95_sd",
          "cache_hit_pct", "dht_hit_pct", "fallback_pct", "p95_monotonic_ok", "saturated", "note"]


def _fmt(v) -> str:
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.3f}"
    return str(v)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def write_csv(all_rows: list[dict]) -> None:
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in all_rows:
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(all_rows)} rows)")


# ---- plot ----
def make_plot(by_curve: dict[str, list[dict]], sat: dict[str, int | None]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    COLD, STEADY, SATC = "#2a78d6", "#8a1c5a", "#c23b22"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    colour = {"cold": COLD, "steady": STEADY}
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    ax = axes[0]
    for curve in CURVES:
        rows = sorted(by_curve.get(curve, []), key=lambda x: x["offered_qps"])
        if not rows:
            continue
        xs = [r["offered_qps"] for r in rows]
        ax.errorbar(xs, [r["success_rate_pct"] for r in rows],
                    yerr=[r["success_sd"] for r in rows], marker="o", ms=5, lw=1.8, capsize=3,
                    color=colour[curve], label=f"{curve}-path")
        if sat.get(curve):
            ax.axvline(sat[curve], color=colour[curve], ls=":", lw=1.2)
    ax.axhline(SAT_THRESHOLD, color=SATC, ls="--", lw=1.0, label="95% line")
    ax.set_xlabel("offered qps"); ax.set_ylabel("success rate (%)"); ax.set_ylim(0, 105)
    ax.set_title(f"A2 — success vs load (N={N}, node-0 entry)")
    ax.legend(frameon=False, fontsize=8)

    ax = axes[1]
    for curve in CURVES:
        rows = sorted(by_curve.get(curve, []), key=lambda x: x["offered_qps"])
        if not rows:
            continue
        xs = [r["offered_qps"] for r in rows]
        ax.errorbar(xs, [r["p95_ms"] for r in rows], yerr=[r["p95_sd"] for r in rows],
                    marker="o", ms=5, lw=1.8, capsize=3, color=colour[curve], label=f"{curve}-path")
    ax.set_xlabel("offered qps"); ax.set_ylabel("p95 latency of successful (ms)"); ax.set_ylim(bottom=0)
    ax.set_title("p95 vs load (monotone ⇒ cache controlled)")
    ax.legend(frameon=False, fontsize=8)

    fig.suptitle("A2 — cache-controlled throughput: cold DHT-path vs steady warm-cache (N=32)",
                 y=1.02, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


def main() -> int:
    ap = argparse.ArgumentParser(description="A2 cache-controlled throughput analysis (issue #33).")
    ap.add_argument("--no-plot", action="store_true")
    args = ap.parse_args()

    if not A2_DIR.is_dir():
        print(f"error: {_rel(A2_DIR)} not found — run experiments/run_a2.sh first")
        return 1

    by_curve: dict[str, list[dict]] = {}
    sat: dict[str, int | None] = {}
    mono: dict[str, tuple[bool, list]] = {}
    all_rows: list[dict] = []
    for curve in CURVES:
        rows = analyse_curve(curve)
        if not rows:
            print(f"  (no snapshots for curve '{curve}')")
            continue
        by_curve[curve] = rows
        sat[curve] = saturation_qps(rows)
        mono[curve] = p95_monotonic(rows)
        ok, seq = mono[curve]
        s = sat[curve]
        note = ""
        if not ok:
            note = "p95 NON-MONOTONIC — cache control failed for this curve, investigate"
        for r in rows:
            r["p95_monotonic_ok"] = ok
            r["saturated"] = (s is not None and r["offered_qps"] >= s)
            r["note"] = note if r["offered_qps"] == rows[0]["offered_qps"] else ""
        all_rows.extend(rows)
        ch_sd, dh_sd = cache_state_constant(rows)
        sat_txt = f"{s} qps" if s is not None else f"none <= {rows[-1]['offered_qps']} qps"
        print(f"  --> curve '{curve}': saturation (first <95%) = {sat_txt}; "
              f"p95 non-decreasing over non-saturated region = {ok}")
        print(f"      cache-state across levels: cache_hit sd={ch_sd:.1f}pp, dht_hit sd={dh_sd:.1f}pp "
              f"(near-0 ⇒ cache pinned, no accumulation-with-load)")
        if not ok:
            print(f"      !! p95 FELL in the non-saturated region: {[(q, round(p, 1)) for q, p in seq]}  "
                  f"(cache control not working — see note)")

    if not all_rows:
        print("error: nothing to write")
        return 1
    write_csv(all_rows)
    if not args.no_plot:
        make_plot(by_curve, sat)

    print("\n== A2 summary ==")
    for curve in CURVES:
        if curve in sat:
            s = sat[curve]
            print(f"  {curve:<7} saturation = {(str(s) + ' qps') if s else 'none in range'};  "
                  f"p95 monotonic = {mono[curve][0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
