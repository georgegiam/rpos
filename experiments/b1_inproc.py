#!/usr/bin/env python3
"""Issue #42 [B1] — Tampering / cache poisoning, in-process ring (fast + robust; no 32-container Docker).

WHY THIS EXISTS — and why it is the PRIMARY (mirrors the b4_inproc.py upgrade). B1's question is
integrity: "if f nodes run MALICIOUS_MODE=lie (node/malicious.py::_h_get_chunk returns the forged
A-record 6.6.6.6 for ANY chunk), how often do clients accept a forged answer, vs the majority-vote
bound?" The answer is a property of node/storage.py::get_chunk's plurality vote + node/query.py's
fallback/cache logic — it is TRANSPORT-INDEPENDENT (the same byte-identical vote runs in-process and
over sockets). Unlike B3's `drop` (which black-holes RPCs and STALLS the in-process transport on 2 s
timeouts), `lie` replies FAST, so the REAL end-to-end node/query.py::resolve_query path runs cleanly
in-process — a faithful, reproducible vehicle for the integrity result, like B4's misroute run.

THE MECHANISM THIS RUN MUST REPRODUCE (and why the DHT starts COLD, unlike b4_inproc which
pre-populates). The committed finding is that the vote achieves only >=1-of-s protection (forged
tracks 1-(1-f)^s), NOT the intended majority bound 3f^2-2f^3. The cause is cold chunks: a `lie`
replica fabricates a value for an unstored chunk, while the honest replicas (which never stored it)
return None and are SKIPPED by the plurality vote — so a lone liar wins 1/1, the forged reply is
cached, and (being a dht_hit) it SUPPRESSES the fallback that would otherwise have populated the
honest replicas. Pre-populating every replica (as B4 does for routing) would hand the honest
replicas the true value and let them out-vote a lone liar 2-to-1 — measuring the WRONG (majority)
bound. So B1 starts each point with an EMPTY DHT and the liars active throughout: forged iff the
chunk's replica set contains >=1 liar, exactly the >=1-of-s structural bound.

METHOD (isolates the attack; seeded throughout, CLAUDE.md §2):
  1. build + converge an in-process ring of MaliciousNode (ids == emulation ids: tests.util.pk_for
     == b1_placement._pk_for), DHT left EMPTY;
  2. per point: reset every store to {} + clear caches, flip f nodes to `lie` (rest honest), run a
     WARM pass (locks each touched domain's value — forged or true) then a MEASURE pass over a fresh
     Zipf sample, counting query-weighted forged-acceptance (ip == FORGED_IP) + distinct-domain
     forged + success + in-process latency;
  3. overlay the realized structural capture (>=1 and >=2 malicious replicas) from b1_placement, read
     over the SAME real ids, plus the analytic i.i.d. bounds.

The f=0 point is the HONEST CONTROL by construction (empty liar set -> 0% forged, votes resolve to
the true value or fallback). The targeted block co-locates the minimum budget (2) on one popular
chunk's replica set (the colluding case that crosses the majority bound).

Latency note: in-process timing has NO network/netem delay, so p50/p95/p99 here are the processing
floor, not realistic DNS latency — the integrity metric (forged-acceptance) is the transport-
independent headline. The original Docker/netem run's realistic latency is retained in
results/B1_tampering_emulation.csv (the cross-check; agrees on forged-acceptance where they overlap).

Run where dnspython is importable — the rpos-node image, or a local venv with it:
    python experiments/b1_inproc.py --queries 3000 --warm 1000 --seeds 5
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import math
import random
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import node.query as _query                                      # noqa: E402
import node.malicious as _malicious                              # noqa: E402
# The measurement reads resolve_query's RETURN value, not the CSV; silence the per-query queries.csv
# append AND the per-lie malicious.csv append (together millions of rows of pure noise).
_query.append_row = lambda *a, **k: None                        # noqa: E731
_malicious.append_row = lambda *a, **k: None                    # noqa: E731

from node.net import Network                                     # noqa: E402
from node.malicious import MaliciousNode, FORGED_IP             # noqa: E402
from node.query import IterativeResolver                         # noqa: E402
from node.tests.util import build_ring                           # noqa: E402
from experiments import b1_placement as b1                       # noqa: E402
from experiments.b3_censorship import _mean_sd                   # noqa: E402 (shared stat)

N = 32
S = 3
PLOT_N = 1024            # frozen (PARAMETERS.md); small => fast in-process admission
SEED = 20260919
ALPHA = 1.0
UPSTREAM_TTL = 300       # B1 uses the DEFAULT upstream TTL (NOT B3's cold-path 0): node 0 caches, so
                         # a locked value (forged or true) persists — the realistic cache lock-in.
F_LEVELS = [0, 10, 20, 30, 40, 50]
MANIFEST = REPO_ROOT / "testbed" / "dns" / "zones" / "MANIFEST.json"
OUT_CSV = REPO_ROOT / "results" / "B1_tampering.csv"


def load_zone() -> dict[str, str]:
    recs = json.loads(MANIFEST.read_text())["records"]
    return {d: r["answer_ip"] for d, r in recs.items()}


def zipf_sample(domains: list[str], alpha: float, m: int, seed: int) -> list[str]:
    """m domains Zipf(alpha) over the popularity-ranked list, matching testbed/query_gen.py."""
    weights = [1.0 / ((i + 1) ** alpha) for i in range(len(domains))]
    return random.Random(seed).choices(domains, weights=weights, k=m)


# ---- percentile helpers (identical maths to b1_tampering.py / a4_replication.py) ----
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


async def build_cold_ring(zone: dict[str, str]):
    """Build an all-honest in-process ring with an EMPTY DHT (cold — the B1 mechanism needs it)."""
    net = Network()
    upstream = IterativeResolver(zone, ttl=UPSTREAM_TTL)
    nodes = await build_ring(MaliciousNode, net, N, upstream=upstream, plot_n=PLOT_N, seed=SEED)
    return net, nodes


def reset_point(nodes, mal_idx: set[int]) -> None:
    """COLD reset: empty every store + clear every cache, then flip exactly `mal_idx` to lie.

    The empty store is essential — it is what makes a lone liar win the plurality vote (honest
    replicas abstain with None) and what lets the forged dht_hit suppress the honest fallback write.
    """
    for i, nd in enumerate(nodes):
        nd.store = {}
        nd.cache = {}
        nd.malicious_mode = "lie" if i in mal_idx else "honest"


async def _pass(nodes, sample: list[str], measure: bool) -> dict | None:
    """Resolve `sample` from node 0. When measure=True, aggregate forged-acceptance + latency."""
    if not measure:
        for d in sample:
            await nodes[0].resolve_query(d)
        return None
    answered = forged = 0
    lat: list[float] = []
    by_dom: dict[str, list[bool]] = {}
    for d in sample:
        t0 = time.monotonic()
        ip, _ttl, _outcome, _hops, _vote = await nodes[0].resolve_query(d)
        lat.append((time.monotonic() - t0) * 1000.0)
        if ip is not None:
            answered += 1
            is_forged = (ip == FORGED_IP)
            forged += int(is_forged)
            by_dom.setdefault(d, []).append(is_forged)
    dom_forged = sum(1 for v in by_dom.values() if sum(v) > len(v) / 2)
    p50, p95, p99 = _pcts(lat)
    nan = float("nan")
    return {
        "forged_pct": 100.0 * forged / answered if answered else nan,
        "distinct_pct": 100.0 * dom_forged / len(by_dom) if by_dom else nan,
        "success_pct": 100.0 * answered / len(sample) if sample else nan,
        "p50": p50, "p95": p95, "p99": p99,
    }


async def measure_point(nodes, mal_idx: set[int], warm_sample, meas_sample) -> dict:
    reset_point(nodes, mal_idx)
    await _pass(nodes, warm_sample, measure=False)      # lock each touched domain (forged or true)
    return await _pass(nodes, meas_sample, measure=True)


FIELDS = ["source", "block", "f_pct", "n_mal", "realized_f_pct", "runs",
          "forged_accepted_pct", "forged_accepted_sd", "forged_distinct_pct",
          "bound_majority_pct", "bound_single_pct",
          "structural_majority_pct", "structural_single_pct",
          "success_rate_pct", "success_sd", "p50_ms", "p95_ms", "p99_ms",
          "target", "target_forged_pct", "note"]


def _fmt(v) -> str:
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.4f}"
    return str(v)


async def run(args) -> int:
    zone = load_zone()
    domains = b1.load_served_domains()
    print(f"[b1-inproc] N={N} s={S} plot_n={PLOT_N} served={len(domains)} "
          f"warm={args.warm} queries/point={args.queries} seeds={args.seeds}")
    print("[b1-inproc] building the in-process ring (all honest, DHT left COLD)...")
    t0 = time.monotonic()
    net, nodes = await build_cold_ring(zone)
    print(f"[b1-inproc] ring ready in {time.monotonic() - t0:.1f}s")

    rows: list[dict] = []
    for f_pct in (args.f_levels or F_LEVELS):
        n_mal = round(f_pct / 100 * N)
        realized_f = n_mal / N
        per, struct_maj, struct_single = [], [], []
        for r in range(args.seeds):
            idx = b1.random_indices(N, n_mal, SEED + r) if n_mal else []
            warm = zipf_sample(domains, ALPHA, args.warm, SEED + 2000 * r + f_pct)
            meas = zipf_sample(domains, ALPHA, args.queries, SEED + 1000 * r + f_pct)
            per.append(await measure_point(nodes, set(idx), warm, meas))
            struct_maj.append(100.0 * b1.structural_capture_fraction(idx, N, S, domains))
            struct_single.append(100.0 * b1.structural_capture_fraction(idx, N, S, domains, thresh=1))
        forged_m, forged_sd = _mean_sd([p["forged_pct"] for p in per])
        succ_m, succ_sd = _mean_sd([p["success_pct"] for p in per])
        rows.append({
            "source": "inproc", "block": "random", "f_pct": f_pct, "n_mal": n_mal,
            "realized_f_pct": 100.0 * realized_f, "runs": len(per),
            "forged_accepted_pct": forged_m, "forged_accepted_sd": forged_sd,
            "forged_distinct_pct": _mean_sd([p["distinct_pct"] for p in per])[0],
            "bound_majority_pct": 100.0 * b1.analytic_bound(realized_f, S),
            "bound_single_pct": 100.0 * b1.effective_bound(realized_f, S),
            "structural_majority_pct": _mean_sd(struct_maj)[0],
            "structural_single_pct": _mean_sd(struct_single)[0],
            "success_rate_pct": succ_m, "success_sd": succ_sd,
            "p50_ms": _mean_sd([p["p50"] for p in per])[0],
            "p95_ms": _mean_sd([p["p95"] for p in per])[0],
            "p99_ms": _mean_sd([p["p99"] for p in per])[0],
            "target": "", "target_forged_pct": float("nan"),
            "note": "honest control" if f_pct == 0 else "",
        })
        print(f"  [random f={f_pct:>2}% n_mal={n_mal:>2} runs={len(per)}] "
              f"forged={forged_m:6.2f}%  single-bound(≥1)={rows[-1]['bound_single_pct']:5.2f}% "
              f"struct(≥1)={rows[-1]['structural_single_pct']:5.2f}%  "
              f"maj-bound={rows[-1]['bound_majority_pct']:5.2f}%  success={succ_m:5.1f}%")

    # targeted / colluding demo: minimum budget (2) co-located on one popular chunk's replica set.
    if not args.no_targeted:
        mal_t, target = b1.targeted_indices(N, S, b1.capture_threshold(S), SEED)
        overall, tgt = [], []
        for r in range(args.target_runs):
            warm = zipf_sample(domains, ALPHA, args.warm, SEED + 5000 + r)
            meas = zipf_sample(domains, ALPHA, args.queries, SEED + 6000 + r)
            m = await measure_point(nodes, set(mal_t), warm, meas)
            overall.append(m["forged_pct"])
            # target chunk: resolve the single target domain on the already-locked ring
            ip, _t, _o, _h, _v = await nodes[0].resolve_query(target)
            tgt.append(100.0 if ip == FORGED_IP else 0.0)
        n_mal = len(mal_t)
        realized_f = n_mal / N
        rows.append({
            "source": "inproc", "block": "targeted", "f_pct": round(100.0 * realized_f),
            "n_mal": n_mal, "realized_f_pct": 100.0 * realized_f, "runs": args.target_runs,
            "forged_accepted_pct": _mean_sd(overall)[0], "forged_accepted_sd": _mean_sd(overall)[1],
            "forged_distinct_pct": float("nan"),
            "bound_majority_pct": 100.0 * b1.analytic_bound(realized_f, S),
            "bound_single_pct": 100.0 * b1.effective_bound(realized_f, S),
            "structural_majority_pct": 100.0 * b1.structural_capture_fraction(mal_t, N, S, domains),
            "structural_single_pct": 100.0 * b1.structural_capture_fraction(mal_t, N, S, domains, thresh=1),
            "success_rate_pct": float("nan"), "success_sd": 0.0,
            "p50_ms": float("nan"), "p95_ms": float("nan"), "p99_ms": float("nan"),
            "target": target, "target_forged_pct": _mean_sd(tgt)[0],
            "note": "colluding: 2 nodes co-located on one chunk's replica set (crosses the bound)",
        })
        print(f"  [targeted target={target} malicious={mal_t} runs={args.target_runs}] "
              f"overall-forged={rows[-1]['forged_accepted_pct']:.2f}%  "
              f"target-forged={rows[-1]['target_forged_pct']:.1f}%")

    for nd in nodes:
        nd.stop()

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\n[b1-inproc] wrote {OUT_CSV.relative_to(REPO_ROOT)} ({len(rows)} rows)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="B1 tampering/cache-poisoning — in-process real-ring run (issue #42).")
    ap.add_argument("--queries", type=int, default=3000, help="measured queries per point (per seed)")
    ap.add_argument("--warm", type=int, default=1000, help="warm-up queries per point (lock caches/DHT)")
    ap.add_argument("--seeds", type=int, default=5, help="independent random placements per f")
    ap.add_argument("--f-levels", type=int, nargs="*", default=None, help="override f%% levels")
    ap.add_argument("--no-targeted", action="store_true")
    ap.add_argument("--target-runs", type=int, default=3)
    args = ap.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
