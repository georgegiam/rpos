#!/usr/bin/env python3
"""Issue #32 [A1] — Latency vs N: analysis, table, and plot (Phase 6, examiner point (iii)).

Reads the per-run snapshots collected by ``experiments/run_a1.sh`` under ``results/a1/``, attributes
each client-observed latency to the resolver outcome logged node-side, computes p50/p95/p99 split
by cache_hit / dht_hit / fallback (and overall) per ring size N — aggregated over the 3 runs with
run-to-run spread — writes ``results/A1_latency_vs_N.csv``, cross-checks the split against the
calibrated ``sim/query_sim.py``, and renders ``results/fig_A1_latency_vs_N.png``.

Why a join (CLAUDE.md "measure, don't assert" / "flag, don't hide")
-------------------------------------------------------------------
Emulation logs latency and outcome in two files that nothing joins at capture time:
  * client-side  ``results/exp_*_nodes.csv``  -> timestamp,domain,resolver_used,latency_ms,success
                 (the exact client-observed RTT — same metric as the Unbound baseline — but NO outcome)
  * node-side    ``ring/<j>/queries.csv``     -> timestamp,domain,hops,outcome,vote_result
                 (the cache/dht/fallback outcome + hops, but NO latency)
We keep the client RTT and attribute it an outcome by pairing, WITHIN each (serving node, domain)
bucket, the client rows and that node's log rows in time order. ``resolver_used=node-<hex>`` maps
to ring index j because node j is created from ``_pk_for(j)`` (byte-identical in node/run_node.py
and testbed/query_gen.py), and node j's container is bind-mounted to ``ring/<j>/``. At 10 qps the
per-node concurrency is low, so the pairing is near-exact; the fraction of client rows that could
NOT be uniquely matched is reported as a diagnostic, never hidden.

Unbound is a single recursive resolver with no notion of N (host mode ignores node count), so its
baseline is collected once (3 runs) and drawn as a flat reference band across every N.

Run:  python3 experiments/a1_latency_vs_n.py            # reads results/a1/, writes CSV + PNG
      python3 experiments/a1_latency_vs_n.py --no-plot  # table + cross-check only
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import math
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
A1_DIR = RESULTS / "a1"
OUT_CSV = RESULTS / "A1_latency_vs_N.csv"
OUT_FIG = RESULTS / "fig_A1_latency_vs_N.png"

OUTCOMES = ["cache_hit", "dht_hit", "fallback"]
SERIES = ["all"] + OUTCOMES                 # rpos series drawn on the plot
RING_BITS = 160                             # node/ids.RING_SIZE = 2**160


# ---- identity mapping (mirrors testbed/query_gen._pk_for/_ring_label and node/run_node._pk_for;
#      reimplemented here with hashlib only so the analysis has no dnspython/node import chain) ----
def _pk_for(i: int) -> bytes:
    return b"node-pk-" + i.to_bytes(4, "big") + b"\x00" * 21


def _ring_label(i: int) -> str:
    rid = int.from_bytes(hashlib.sha256(_pk_for(i)).digest(), "big") % (1 << RING_BITS)
    return "node-" + format(rid, "x")[:12]


def _canon(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


# ---- percentile — linear-interpolated, identical to sim/query_sim.py._percentile ----
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


def _parse_node_ts(ts: str) -> float:
    """ISO-8601 (with tz) -> epoch seconds, for time-ordering node rows within a bucket."""
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return 0.0


# ---------------------------------------------------------------------------------------
# One run: join client latency <-> node outcome.
# ---------------------------------------------------------------------------------------
class JoinResult:
    def __init__(self) -> None:
        self.rows: list[dict] = []          # each: {domain, latency, success, outcome}
        self.n_client = 0
        self.n_matched = 0                  # client rows given a node outcome


def load_client_rows(path: Path) -> list[dict]:
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out.append({
                "ts": float(r["timestamp"]),
                "domain": _canon(r["domain"]),
                "label": r["resolver_used"],
                "latency": float(r["latency_ms"]),
                "success": str(r["success"]).strip().lower() == "true",
            })
    return out


def load_node_rows(run_dir: Path) -> dict[str, list[dict]]:
    """Return {ring_label: [ {ts, domain, outcome, hops}, ... ]} from ring/<j>_queries.csv files."""
    by_label: dict[str, list[dict]] = defaultdict(list)
    ring_dir = run_dir / "ring"
    if not ring_dir.is_dir():
        return by_label
    for p in sorted(ring_dir.glob("*_queries.csv")):
        try:
            j = int(p.name.split("_", 1)[0])
        except ValueError:
            continue
        label = _ring_label(j)
        with open(p, newline="") as f:
            for r in csv.DictReader(f):
                by_label[label].append({
                    "ts": _parse_node_ts(r["timestamp"]),
                    "domain": _canon(r["domain"]),
                    "outcome": r["outcome"],
                    "hops": int(r["hops"]) if r.get("hops", "").strip() else 0,
                })
    return by_label


def join_run(run_dir: Path) -> JoinResult | None:
    client_csv = run_dir / "client.csv"
    if not client_csv.exists():
        return None
    client = load_client_rows(client_csv)
    node_by_label = load_node_rows(run_dir)

    # bucket client rows by (label, domain); pair with the same node bucket in time order
    client_buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for c in client:
        client_buckets[(c["label"], c["domain"])].append(c)
    node_buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for label, rows in node_by_label.items():
        for nr in rows:
            node_buckets[(label, nr["domain"])].append(nr)

    res = JoinResult()
    res.n_client = len(client)
    for key, crows in client_buckets.items():
        crows.sort(key=lambda x: x["ts"])
        nrows = sorted(node_buckets.get(key, []), key=lambda x: x["ts"])
        for i, c in enumerate(crows):
            outcome = nrows[i]["outcome"] if i < len(nrows) else "unmatched"
            if outcome != "unmatched":
                res.n_matched += 1
            res.rows.append({"domain": c["domain"], "latency": c["latency"],
                             "success": c["success"], "outcome": outcome})
    return res


# ---------------------------------------------------------------------------------------
# Aggregate across runs -> per-(N, series) mean percentiles + run-to-run sd.
# ---------------------------------------------------------------------------------------
def _mean_sd(vals: list[float]) -> tuple[float, float]:
    vals = [v for v in vals if not math.isnan(v)]
    if not vals:
        return float("nan"), 0.0
    m = statistics.fmean(vals)
    sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
    return m, sd


def aggregate_rpos(n: int, run_dirs: list[Path]) -> list[dict]:
    """One dict per series (all + each outcome) for size n, aggregated over runs."""
    # per-run percentiles for each series
    per_run: dict[str, dict[str, list[float]]] = {s: {"p50": [], "p95": [], "p99": []}
                                                   for s in SERIES}
    run_success: list[float] = []
    run_share: dict[str, list[float]] = {o: [] for o in OUTCOMES}
    run_outcome_success: dict[str, list[float]] = {o: [] for o in OUTCOMES}
    total_rows = {s: 0 for s in SERIES}
    matched, client_total = 0, 0
    n_runs = 0

    for rd in run_dirs:
        jr = join_run(rd)
        if jr is None or not jr.rows:
            continue
        n_runs += 1
        matched += jr.n_matched
        client_total += jr.n_client
        succ = [r for r in jr.rows if r["success"]]
        run_success.append(100.0 * len(succ) / len(jr.rows) if jr.rows else float("nan"))

        # overall (success rows, matches summarise() convention)
        p50, p95, p99 = _pcts([r["latency"] for r in succ])
        per_run["all"]["p50"].append(p50); per_run["all"]["p95"].append(p95)
        per_run["all"]["p99"].append(p99); total_rows["all"] += len(succ)

        for o in OUTCOMES:
            o_all = [r for r in jr.rows if r["outcome"] == o]
            o_succ = [r for r in o_all if r["success"]]
            run_share[o].append(100.0 * len(o_all) / len(jr.rows) if jr.rows else float("nan"))
            run_outcome_success[o].append(
                100.0 * len(o_succ) / len(o_all) if o_all else float("nan"))
            p50, p95, p99 = _pcts([r["latency"] for r in o_succ])
            per_run[o]["p50"].append(p50); per_run[o]["p95"].append(p95)
            per_run[o]["p99"].append(p99); total_rows[o] += len(o_succ)

    if n_runs == 0:
        return []

    match_pct = 100.0 * matched / client_total if client_total else float("nan")
    print(f"  [N={n:>2}] runs={n_runs}  join match-quality: "
          f"{matched}/{client_total} client rows attributed ({match_pct:.1f}%)")

    rows = []
    for s in SERIES:
        p50_m, p50_sd = _mean_sd(per_run[s]["p50"])
        p95_m, p95_sd = _mean_sd(per_run[s]["p95"])
        p99_m, p99_sd = _mean_sd(per_run[s]["p99"])
        if s == "all":
            share = 100.0
            succ_pct, _ = _mean_sd(run_success)
        else:
            share, _ = _mean_sd(run_share[s])
            succ_pct, _ = _mean_sd(run_outcome_success[s])
        rows.append({
            "n": n, "resolver": "rpos", "outcome": s, "runs": n_runs,
            "n_rows": total_rows[s], "share_pct": share, "success_pct": succ_pct,
            "p50_ms": p50_m, "p95_ms": p95_m, "p99_ms": p99_m,
            "p50_sd": p50_sd, "p95_sd": p95_sd, "p99_sd": p99_sd,
        })
    return rows


def aggregate_unbound(run_dirs: list[Path]) -> dict | None:
    per_run = {"p50": [], "p95": [], "p99": []}
    run_success = []
    total = 0
    n_runs = 0
    for rd in run_dirs:
        client_csv = rd / "client.csv"
        if not client_csv.exists():
            continue
        rows = load_client_rows(client_csv)
        if not rows:
            continue
        n_runs += 1
        succ = [r for r in rows if r["success"]]
        run_success.append(100.0 * len(succ) / len(rows))
        p50, p95, p99 = _pcts([r["latency"] for r in succ])
        per_run["p50"].append(p50); per_run["p95"].append(p95); per_run["p99"].append(p99)
        total += len(succ)
    if n_runs == 0:
        return None
    p50_m, p50_sd = _mean_sd(per_run["p50"])
    p95_m, p95_sd = _mean_sd(per_run["p95"])
    p99_m, p99_sd = _mean_sd(per_run["p99"])
    succ_pct, _ = _mean_sd(run_success)
    print(f"  [unbound] runs={n_runs}  p50={p50_m:.1f} p95={p95_m:.1f} p99={p99_m:.1f} ms")
    return {"runs": n_runs, "n_rows": total, "success_pct": succ_pct,
            "p50_ms": p50_m, "p95_ms": p95_m, "p99_ms": p99_m,
            "p50_sd": p50_sd, "p95_sd": p95_sd, "p99_sd": p99_sd}


# ---------------------------------------------------------------------------------------
# Cross-check the rpos per-outcome split against the calibrated simulator (#26/#29).
# ---------------------------------------------------------------------------------------
def sim_split(n: int) -> dict | None:
    try:
        sys.path.insert(0, str(REPO_ROOT))
        from sim.query_sim import run_workload  # noqa: E402
    except Exception as e:                       # pragma: no cover
        print(f"  [xcheck] sim import failed ({e}); skipping")
        return None
    _, recs = run_workload(n=n, qps=10, duration_s=30, warmup_s=30, seed=20260919)
    out = {}
    for s in SERIES:
        lat = [r.latency_ms for r in recs] if s == "all" \
            else [r.latency_ms for r in recs if r.outcome == s]
        p50, p95, p99 = _pcts(lat)
        out[s] = (p50, p95, p99)
    return out


def cross_check(rpos_rows: list[dict]) -> None:
    print("\n== sim cross-check (calibrated sim/query_sim.py; non-gating, documented) ==")
    by_no = {(r["n"], r["outcome"]): r for r in rpos_rows if r["resolver"] == "rpos"}
    for n in (8, 32):
        sim = sim_split(n)
        if sim is None:
            return
        for s in SERIES:
            emu = by_no.get((n, s))
            if emu is None or math.isnan(emu["p50_ms"]):
                continue
            sp50 = sim[s][0]
            rel = 100.0 * abs(sp50 - emu["p50_ms"]) / emu["p50_ms"] if emu["p50_ms"] else float("nan")
            print(f"  N={n:>2} {s:<9} p50  emu {emu['p50_ms']:7.1f}  sim {sp50:7.1f}  "
                  f"rel {rel:5.1f}%")


# ---------------------------------------------------------------------------------------
# CSV + plot.
# ---------------------------------------------------------------------------------------
FIELDS = ["n", "resolver", "outcome", "runs", "n_rows", "share_pct", "success_pct",
          "p50_ms", "p95_ms", "p99_ms", "p50_sd", "p95_sd", "p99_sd"]


def _fmt(v) -> str:
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.3f}"
    return str(v)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def write_csv(rows: list[dict]) -> None:
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


def make_plot(rpos_rows: list[dict], unbound: dict | None, ns: list[int]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # style mirrors phase1/plots.py (validated colorblind-safe palette, recessive grid)
    PAL = {"all": "#0b0b0b", "cache_hit": "#1baf7a", "dht_hit": "#2a78d6", "fallback": "#eb6834"}
    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    UNB = "#8a1c5a"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })

    idx = {(r["n"], r["outcome"]): r for r in rpos_rows if r["resolver"] == "rpos"}
    metrics = [("p50_ms", "p50_sd", "p50 (median)"),
               ("p95_ms", "p95_sd", "p95"),
               ("p99_ms", "p99_sd", "p99")]
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.2), sharex=True)

    for ax, (mk, sdk, title) in zip(axes, metrics):
        for s in SERIES:
            xs, ys, es = [], [], []
            for n in ns:
                r = idx.get((n, s))
                if r is None or math.isnan(r[mk]):
                    continue
                xs.append(n); ys.append(r[mk]); es.append(r[sdk])
            if xs:
                ax.errorbar(xs, ys, yerr=es, marker="o", ms=4, lw=1.6, capsize=3,
                            color=PAL[s], label=s if ax is axes[0] else None)
        if unbound is not None and not math.isnan(unbound[mk]):
            ax.axhline(unbound[mk], color=UNB, ls="--", lw=1.4,
                       label="Unbound" if ax is axes[0] else None)
            ax.axhspan(unbound[mk] - unbound[sdk], unbound[mk] + unbound[sdk],
                       color=UNB, alpha=0.10)
        ax.set_xscale("log", base=2)
        ax.set_xticks(ns); ax.set_xticklabels([str(n) for n in ns])
        ax.set_yscale("log")
        ax.set_xlabel("ring size N")
        ax.set_title(title)
    axes[0].set_ylabel("latency (ms)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=len(labels),
               frameon=False, bbox_to_anchor=(0.5, 1.02))
    fig.suptitle("A1 — resolver query latency vs ring size N (split by outcome), vs Unbound",
                 y=1.10, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
def discover_ns() -> list[int]:
    ns = []
    if A1_DIR.is_dir():
        for d in A1_DIR.glob("N*"):
            if d.is_dir() and d.name[1:].isdigit():
                ns.append(int(d.name[1:]))
    return sorted(ns)


def run_dirs_for(n: int) -> list[Path]:
    base = A1_DIR / f"N{n}"
    return sorted([d for d in base.glob("run*") if d.is_dir()]) if base.is_dir() else []


def main() -> int:
    ap = argparse.ArgumentParser(description="A1 latency-vs-N analysis (issue #32).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--no-xcheck", action="store_true", help="skip the sim cross-check")
    args = ap.parse_args()

    if not A1_DIR.is_dir():
        print(f"error: {A1_DIR} not found — run experiments/run_a1.sh first", file=sys.stderr)
        return 1
    ns = discover_ns()
    if not ns:
        print(f"error: no N*/ snapshots under {A1_DIR} — run experiments/run_a1.sh first",
              file=sys.stderr)
        return 1

    print(f"== A1 analysis: N = {ns} ==")
    rpos_rows: list[dict] = []
    for n in ns:
        rpos_rows.extend(aggregate_rpos(n, run_dirs_for(n)))

    unbound_dirs = sorted([d for d in (A1_DIR / "unbound").glob("run*") if d.is_dir()]) \
        if (A1_DIR / "unbound").is_dir() else []
    unbound = aggregate_unbound(unbound_dirs) if unbound_dirs else None

    # emit CSV: rpos rows, then an Unbound flat-band row per N (self-contained table per N)
    all_rows = list(rpos_rows)
    if unbound is not None:
        for n in ns:
            all_rows.append({"n": n, "resolver": "unbound", "outcome": "all",
                             "share_pct": 100.0, **unbound})
    write_csv(all_rows)

    if not args.no_xcheck:
        cross_check(rpos_rows)

    if not args.no_plot:
        make_plot(rpos_rows, unbound, ns)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
