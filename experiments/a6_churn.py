#!/usr/bin/env python3
"""Issue #37 [A6] — Churn: lookup success vs session length: analysis, table, plot (Phase 6, (ii)/(iii)).

Reads the per-run snapshots collected by ``experiments/run_a6.sh`` under ``results/a6/`` (one dir per
mean session length: s30/s60/s120/s300/sinf), attributes each client-observed latency to the resolver
outcome logged node-side (the A1 join), and reports, per session length aggregated over the 3 runs:
  * RAW-DHT lookup success (HEADLINE) — a lookup counts as available iff the ring served it WITHOUT
    the DNS-hierarchy fallback (outcome in {cache_hit, dht_hit}); a fallback = a DHT miss. This is
    comparable to sim/churn_sim.py's raw-DHT headline and is the only metric that shows a churn curve.
  * end-to-end client success (secondary) — what the user observes; stays ~100% because the resolver
    fallback re-fetches lost chunks, which is exactly WHY the raw-DHT view is the headline.
  * p50/p95/p99 client latency (issue #37 asks for p95).
  * fallback %, mean live population (from churn_events.csv).
Writes ``results/A6_churn.csv`` + ``results/fig_A6_churn.png`` and cross-checks the raw-DHT curve
against ``sim/churn_sim.py`` re-run at N=32 for the same session set.

Why a join (CLAUDE.md "measure, don't assert" / "flag, don't hide")
-------------------------------------------------------------------
Emulation logs latency and outcome in two files nothing joins at capture time:
  * client-side  ``client.csv``            -> timestamp,domain,resolver_used,latency_ms,success
  * node-side    ``ring/<j>_queries.csv``  -> timestamp,domain,hops,outcome,vote_result
We pair them WITHIN each (serving node, domain) bucket in time order (identical to A1). Because A6
sends every query to node 0 (--ring-nodes 1), the client label is node-0's ring-id, but the node that
LOGS the outcome is whichever node actually served the chunk — so we pair on the node-side logs across
ALL nodes by (domain) and rely on the per-domain time order. The fraction of client rows that could
NOT be matched is reported, never hidden.

Model note (flag, don't hide): the emulation has NO active chunk re-replication (no repair loop in
node/*), unlike churn_sim which restores the full replica set every 1 s. In emulation the only
recovery is the fallback re-fetching-and-storing a chunk on read (so popular Zipf chunks self-heal,
unpopular ones do not). So the emulation raw-DHT curve is a DIFFERENT, more pessimistic model than the
sim's — the sim is a directional cross-check, not a fitted match (as in A5). churn_sim also has no
latency model, so its rows carry success only.

Run:  python3 experiments/a6_churn.py            # reads results/a6/ + runs sim, writes CSV + PNG
      python3 experiments/a6_churn.py --no-plot  # table + cross-check only
      python3 experiments/a6_churn.py --sim-only # skip emulation (fast, no Docker snapshots)
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
A6_DIR = RESULTS / "a6"
OUT_CSV = RESULTS / "A6_churn.csv"
OUT_FIG = RESULTS / "fig_A6_churn.png"

# import the churn simulator for the sim cross-check (byte-identical, imported not modified).
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from sim.churn_sim import (  # noqa: E402
    DEFAULT_SEED, DEFAULT_DURATION_S, DEFAULT_WARMUP_S, DEFAULT_REPAIR_S, run_churn,
)

# frozen A6 workload (PARAMETERS.md / run_a6.sh) — recorded per row for a self-contained deliverable
A6_N = 32
A6_QPS = 10.0
A6_DURATION_S = 120            # emulation measured window (issue #37)
SEED = DEFAULT_SEED
SESSIONS = (30.0, 60.0, 120.0, 300.0, float("inf"))   # mean session lengths swept
HIT_OUTCOMES = {"cache_hit", "dht_hit"}               # served WITHOUT fallback == raw-DHT available
SIM_BIG_SESSION_S = 1e7        # stand-in for "inf" (no churn) in the sim sweep


# ---- session <-> filesystem tag (30 -> s30, inf -> sinf) ----
def stag(L: float) -> str:
    return "sinf" if not math.isfinite(L) else f"s{int(L)}"


# ---- identity mapping (mirrors testbed/query_gen._pk_for/_ring_label; hashlib-only) ----
def _pk_for(i: int) -> bytes:
    return b"node-pk-" + i.to_bytes(4, "big") + b"\x00" * 21


def _ring_label(i: int) -> str:
    rid = int.from_bytes(hashlib.sha256(_pk_for(i)).digest(), "big") % (1 << 160)
    return "node-" + format(rid, "x")[:12]


def _canon(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


# ---- percentile / stats helpers — identical to experiments/a1_latency_vs_n.py ----
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


def _parse_node_ts(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return 0.0


# ---------------------------------------------------------------------------------------
# One run: join client latency <-> node outcome, then derive the availability metrics.
# ---------------------------------------------------------------------------------------
def load_client_rows(path: Path) -> list[dict]:
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out.append({
                "ts": float(r["timestamp"]),
                "domain": _canon(r["domain"]),
                "latency": float(r["latency_ms"]),
                "success": str(r["success"]).strip().lower() == "true",
            })
    return out


def load_node_rows(run_dir: Path) -> dict[str, list[dict]]:
    """Return {domain: [ {ts, outcome}, ... ]} pooled over ALL ring/<j>_queries.csv files.

    A6 sends every query to node 0, but the OUTCOME is logged by whichever node served the chunk, so
    (unlike A1's per-(node,domain) bucketing) we pool node-side rows by domain across the whole ring.
    """
    by_domain: dict[str, list[dict]] = defaultdict(list)
    ring_dir = run_dir / "ring"
    if not ring_dir.is_dir():
        return by_domain
    for p in sorted(ring_dir.glob("*_queries.csv")):
        with open(p, newline="") as f:
            for r in csv.DictReader(f):
                by_domain[_canon(r["domain"])].append({
                    "ts": _parse_node_ts(r["timestamp"]),
                    "outcome": str(r["outcome"]).strip(),
                })
    return by_domain


def load_mean_live_pop(run_dir: Path, n: int) -> float:
    """Mean live population over the churn window from churn_events.csv; N when no churn (inf)."""
    ev = run_dir / "churn_events.csv"
    if not ev.exists():
        return float(n)
    live = []
    with open(ev, newline="") as f:
        for r in csv.DictReader(f):
            try:
                live.append(int(r["live_pop"]))
            except (KeyError, ValueError):
                continue
    return statistics.fmean(live) if live else float(n)


class RunMetrics:
    def __init__(self) -> None:
        self.raw_dht_success = float("nan")   # % of MATCHED lookups served without fallback
        self.e2e_success = float("nan")       # % of client lookups that returned an answer
        self.fallback_pct = float("nan")
        self.p50 = self.p95 = self.p99 = float("nan")
        self.mean_live_pop = float("nan")
        self.n_client = 0
        self.n_matched = 0


def analyse_run(run_dir: Path, n: int) -> RunMetrics | None:
    client_csv = run_dir / "client.csv"
    if not client_csv.exists():
        return None
    client = load_client_rows(client_csv)
    if not client:
        return None
    node_by_domain = load_node_rows(run_dir)

    # pair client rows to node outcomes per domain, in time order (A1 pattern, pooled by domain)
    client_buckets: dict[str, list[dict]] = defaultdict(list)
    for c in client:
        client_buckets[c["domain"]].append(c)

    hits = fallbacks = matched = 0
    for domain, crows in client_buckets.items():
        crows.sort(key=lambda x: x["ts"])
        nrows = sorted(node_by_domain.get(domain, []), key=lambda x: x["ts"])
        for i, _c in enumerate(crows):
            if i >= len(nrows):
                continue                       # unmatched — reported via match-quality, not counted
            outcome = nrows[i]["outcome"]
            matched += 1
            if outcome in HIT_OUTCOMES:
                hits += 1
            elif outcome == "fallback":
                fallbacks += 1

    m = RunMetrics()
    m.n_client = len(client)
    m.n_matched = matched
    if matched:
        m.raw_dht_success = 100.0 * hits / matched
        m.fallback_pct = 100.0 * fallbacks / matched
    ok = [r for r in client if r["success"]]
    m.e2e_success = 100.0 * len(ok) / len(client)
    m.p50, m.p95, m.p99 = _pcts([r["latency"] for r in ok])
    m.mean_live_pop = load_mean_live_pop(run_dir, n)
    return m


def emulation_row(L: float) -> dict | None:
    sdir = A6_DIR / stag(L)
    if not sdir.is_dir():
        return None
    runs = sorted(d for d in sdir.glob("run*") if d.is_dir())
    raw, e2e, p95s, fb, live = [], [], [], [], []
    p50s, p99s = [], []
    matched = client_total = used = 0
    for run in runs:
        m = analyse_run(run, A6_N)
        if m is None:
            continue
        used += 1
        matched += m.n_matched
        client_total += m.n_client
        raw.append(m.raw_dht_success); e2e.append(m.e2e_success); fb.append(m.fallback_pct)
        p50s.append(m.p50); p95s.append(m.p95); p99s.append(m.p99); live.append(m.mean_live_pop)
    if used == 0:
        return None
    match_pct = 100.0 * matched / client_total if client_total else float("nan")
    print(f"  [{stag(L):>5}] runs={used}  join match-quality: "
          f"{matched}/{client_total} client rows attributed ({match_pct:.1f}%)")
    raw_m, raw_sd = _mean_sd(raw)
    e2e_m, e2e_sd = _mean_sd(e2e)
    p95_m, p95_sd = _mean_sd(p95s)
    return {
        "source": "emulation", "n": A6_N, "mean_session_s": L, "qps": A6_QPS,
        "duration_s": A6_DURATION_S, "runs": used,
        "raw_dht_success_pct": raw_m, "raw_dht_success_sd": raw_sd,
        "e2e_success_pct": e2e_m, "e2e_success_sd": e2e_sd,
        "p50_ms": _mean_sd(p50s)[0], "p95_ms": p95_m, "p99_ms": _mean_sd(p99s)[0], "p95_sd": p95_sd,
        "fallback_pct": _mean_sd(fb)[0], "mean_live_pop": _mean_sd(live)[0],
        "note": "raw-DHT headline; no active re-replication (fallback-on-read only)",
    }


# ---------------------------------------------------------------------------------------
# Simulation cross-check: sim/churn_sim.py re-run at N=32 for the same session set.
# ---------------------------------------------------------------------------------------
def sim_row(L: float) -> dict:
    session = SIM_BIG_SESSION_S if not math.isfinite(L) else L
    res, _ = run_churn(n=A6_N, mean_session_s=session, duration_s=DEFAULT_DURATION_S,
                       warmup_s=DEFAULT_WARMUP_S, repair_s=DEFAULT_REPAIR_S,
                       lookup_qps=A6_QPS, seed=SEED)
    return {
        "source": "sim", "n": A6_N, "mean_session_s": L, "qps": A6_QPS,
        "duration_s": DEFAULT_DURATION_S, "runs": 1,
        "raw_dht_success_pct": 100.0 * res.success_rate, "raw_dht_success_sd": 0.0,
        "e2e_success_pct": float("nan"), "e2e_success_sd": 0.0,
        "p50_ms": float("nan"), "p95_ms": float("nan"), "p99_ms": float("nan"), "p95_sd": 0.0,
        "fallback_pct": 100.0 * (1.0 - res.success_rate), "mean_live_pop": res.mean_live_pop,
        "note": f"data-availability model, 1s repair, {res.chunks_lost} chunks lost, no latency",
    }


# ---------------------------------------------------------------------------------------
# CSV.
# ---------------------------------------------------------------------------------------
FIELDS = ["source", "n", "mean_session_s", "qps", "duration_s", "runs",
          "raw_dht_success_pct", "raw_dht_success_sd", "e2e_success_pct", "e2e_success_sd",
          "p50_ms", "p95_ms", "p99_ms", "p95_sd", "fallback_pct", "mean_live_pop", "note"]


def _fmt(v) -> str:
    if isinstance(v, float):
        if math.isnan(v):
            return ""
        if math.isinf(v):
            return "inf"
        return f"{v:.4f}"
    return str(v)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def _sortkey(r: dict):
    L = r["mean_session_s"]
    return (0 if r["source"] == "emulation" else 1, math.inf if not math.isfinite(L) else L)


def write_csv(rows: list[dict]) -> None:
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=_sortkey):
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# ---------------------------------------------------------------------------------------
# Plot: success vs session length (emulation raw-DHT + e2e, sim raw-DHT) + p95 vs session.
# inf (no-churn) is drawn as a reference line, finite sessions on a log-x axis (A1 idiom).
# ---------------------------------------------------------------------------------------
def make_plot(rows: list[dict]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import NullLocator

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    EMU, SIM, E2E = "#2a78d6", "#8a1c5a", "#1baf7a"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })

    def split(source):
        fin = sorted([r for r in rows if r["source"] == source and math.isfinite(r["mean_session_s"])],
                     key=lambda r: r["mean_session_s"])
        inf = next((r for r in rows if r["source"] == source and not math.isfinite(r["mean_session_s"])),
                   None)
        return fin, inf

    emu_fin, emu_inf = split("emulation")
    sim_fin, sim_inf = split("sim")
    finite_sessions = sorted({r["mean_session_s"] for r in rows if math.isfinite(r["mean_session_s"])})

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    # --- panel 1: success rate vs mean session length ---
    ax = axes[0]
    if emu_fin:
        ax.errorbar([r["mean_session_s"] for r in emu_fin],
                    [r["raw_dht_success_pct"] for r in emu_fin],
                    yerr=[r["raw_dht_success_sd"] for r in emu_fin],
                    marker="o", ms=6, lw=1.8, capsize=3, color=EMU, label="emulation raw-DHT")
        ax.errorbar([r["mean_session_s"] for r in emu_fin],
                    [r["e2e_success_pct"] for r in emu_fin],
                    yerr=[r["e2e_success_sd"] for r in emu_fin],
                    marker="^", ms=5, lw=1.4, capsize=3, color=E2E, label="emulation end-to-end")
    if sim_fin:
        ax.plot([r["mean_session_s"] for r in sim_fin],
                [r["raw_dht_success_pct"] for r in sim_fin],
                marker="s", ms=6, lw=1.6, ls="--", color=SIM, label="sim raw-DHT")
    if emu_inf and not math.isnan(emu_inf["raw_dht_success_pct"]):
        ax.axhline(emu_inf["raw_dht_success_pct"], color=EMU, ls=":", lw=1.2,
                   label="emulation no-churn (∞)")
    ax.set_xscale("log")
    if finite_sessions:
        ax.xaxis.set_minor_locator(NullLocator())
        ax.set_xticks(finite_sessions)
        ax.set_xticklabels([str(int(s)) for s in finite_sessions])
    ax.set_xlabel("mean node session length (s)")
    ax.set_ylabel("lookup success (%)")
    ax.set_ylim(0, 105)
    ax.set_title("A6 — lookup success vs session length (N=32)")
    if ax.get_legend_handles_labels()[0]:
        ax.legend(frameon=False, fontsize=8)

    # --- panel 2: p95 latency vs session length (emulation only; sim has no latency model) ---
    ax = axes[1]
    if emu_fin:
        ax.errorbar([r["mean_session_s"] for r in emu_fin],
                    [r["p95_ms"] for r in emu_fin], yerr=[r["p95_sd"] for r in emu_fin],
                    marker="o", ms=6, lw=1.8, capsize=3, color=EMU, label="emulation p95")
    if emu_inf and not math.isnan(emu_inf["p95_ms"]):
        ax.axhline(emu_inf["p95_ms"], color=EMU, ls=":", lw=1.2, label="no-churn (∞)")
    ax.set_xscale("log")
    if finite_sessions:
        ax.xaxis.set_minor_locator(NullLocator())
        ax.set_xticks(finite_sessions)
        ax.set_xticklabels([str(int(s)) for s in finite_sessions])
    ax.set_xlabel("mean node session length (s)")
    ax.set_ylabel("p95 latency (ms)")
    ax.set_ylim(bottom=0)
    ax.set_title("p95 latency vs session length (N=32, 10 qps)")
    if ax.get_legend_handles_labels()[0]:
        ax.legend(frameon=False, fontsize=8)

    fig.suptitle("A6 — churn: lookup availability & latency vs session length (emulation + sim)",
                 y=1.02, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="A6 churn analysis (issue #37).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--sim-only", action="store_true",
                    help="skip emulation snapshots (fast sim-only smoke, no Docker needed)")
    args = ap.parse_args()

    rows: list[dict] = []

    # --- emulation (per session length) ---
    if not args.sim_only:
        if not A6_DIR.is_dir():
            print(f"note: {_rel(A6_DIR)} not found — run experiments/run_a6.sh first "
                  f"(continuing with sim only)", file=sys.stderr)
        else:
            print("== A6: emulation (results/a6/) ==")
            for L in SESSIONS:
                r = emulation_row(L)
                if r is None:
                    print(f"  [{stag(L):>5}] no snapshots under {_rel(A6_DIR / stag(L))} — skipped")
                    continue
                rows.append(r)
                print(f"  [{stag(L):>5}] runs={r['runs']} raw-DHT={r['raw_dht_success_pct']:5.1f}% "
                      f"e2e={r['e2e_success_pct']:5.1f}% p95={r['p95_ms']:.0f}ms "
                      f"live≈{r['mean_live_pop']:.1f}")
            if not rows:
                print("  (no emulation snapshots found — run experiments/run_a6.sh, or use --sim-only)")

    # --- simulation cross-check: churn_sim at N=32 for the same session set ---
    print(f"\n== A6: simulation @ N={A6_N}, {A6_QPS:g} qps (sim/churn_sim.py, seed {SEED}) ==")
    for L in SESSIONS:
        r = sim_row(L)
        rows.append(r)
        lbl = "∞" if not math.isfinite(L) else f"{int(L)}s"
        print(f"  [session {lbl:>4}] raw-DHT={r['raw_dht_success_pct']:5.1f}%  {r['note']}")

    if not rows:
        print("error: nothing to write", file=sys.stderr)
        return 1

    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
