"""Phase 5 (#30, P5-6) — scale the calibrated simulator to N = 1,000 / 5,000 / 10,000.

Runs the #29-calibrated ``query_sim`` (proc_delay_ms=18, FALLBACK_STEP_MS=100, routing hop = full
RTT; measured 5/50 ms netem frozen) at large N under qps=100, 60 s measured (+30 s warm-up, the
frozen PARAMETERS.md window), seed 20260919. Records per N: median hops, p50/p95/p99 latency,
throughput, and per-node message load. Writes ``results/sim_scale.csv``.

**Per-node message load** is derived from each query's routing outcome, counting exactly the ring
RPCs the latency model charges (``query_sim.resolve``): a round trip = req+resp = 2 messages.

    cache_hit : 0 ring RPCs (served locally)
    dht_hit   : route_hops  + 1 (get_succ_list) + S (replica reads)
    fallback  : the failed DHT read attempt [route_hops + 1 + S] + the store-back
                [re-route route_hops + 1 + S write] = 2*(route_hops + 1 + S)
                (the FALLBACK_STEPS upstream referrals go to the DNS hierarchy, not ring nodes,
                so they are not ring messages).

where ``route_hops`` is the find_successor path length (``dht_hit`` = ``rec.hops``; ``fallback`` =
``rec.hops - FALLBACK_STEPS``). Aggregate ring messages / N / duration = messages/node/s.

Run:  ``python -m sim.scale_sim``
"""
from __future__ import annotations

import csv
import math
import os
import statistics
import sys
from pathlib import Path

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from sim.query_sim import (  # noqa: E402
    DEFAULT_SEED,
    FALLBACK_STEPS,
    S,
    run_workload,
    summarize,
)

_HERE = Path(__file__).resolve().parent
_SCALE_CSV = _HERE.parent / "results" / "sim_scale.csv"

SCALES = (1000, 5000, 10000)
QPS = 100.0
DURATION_S = 60
WARMUP_S = 30          # frozen PARAMETERS.md warm-up window


def ring_round_trips(outcome: str, hops: int) -> int:
    """Ring RPC round trips for one query, mirroring query_sim.resolve's RPC structure."""
    if outcome == "cache_hit":
        return 0
    if outcome == "dht_hit":
        route_hops = hops
        return route_hops + 1 + S                       # route + get_succ_list + S replica reads
    route_hops = hops - FALLBACK_STEPS                  # fallback: recover the routing component
    read_attempt = route_hops + 1 + S                   # failed DHT read
    store_back = route_hops + 1 + S                     # re-route + S replica writes
    return read_attempt + store_back


def route_hops_of(outcome: str, hops: int) -> int | None:
    """Pure find_successor path length (for the ½·log₂N theory check); None for cache hits."""
    if outcome == "cache_hit":
        return None
    return hops if outcome == "dht_hit" else hops - FALLBACK_STEPS


def run_scale(n: int) -> dict:
    _sim, rows = run_workload(n=n, qps=QPS, duration_s=DURATION_S, warmup_s=WARMUP_S,
                              seed=DEFAULT_SEED)
    s = summarize(rows)

    total_rt = sum(ring_round_trips(r.outcome, r.hops) for r in rows)
    total_msgs = 2 * total_rt
    msgs_per_node_per_s = total_msgs / n / DURATION_S
    throughput_qps = len(rows) / DURATION_S

    route_hops = [route_hops_of(r.outcome, r.hops) for r in rows]
    route_hops = [h for h in route_hops if h is not None]
    mean_route_hops = statistics.fmean(route_hops) if route_hops else 0.0

    return {
        "n": n, "qps": QPS, "duration_s": DURATION_S,
        "measured_queries": len(rows),
        "median_hops": s["hop_median"],
        "mean_route_hops": round(mean_route_hops, 3),
        "p50_ms": round(s["p50_ms"], 3),
        "p95_ms": round(s["p95_ms"], 3),
        "p99_ms": round(s["p99_ms"], 3),
        "throughput_qps": round(throughput_qps, 3),
        "msgs_per_node_per_s": round(msgs_per_node_per_s, 4),
        "total_ring_messages": total_msgs,
    }


HEADER = ["n", "qps", "duration_s", "measured_queries", "median_hops", "mean_route_hops",
          "p50_ms", "p95_ms", "p99_ms", "throughput_qps", "msgs_per_node_per_s",
          "total_ring_messages"]


def main() -> int:
    results = []
    for n in SCALES:
        print(f"running N={n} (qps={QPS:g}, {DURATION_S}s + {WARMUP_S}s warm-up, seed {DEFAULT_SEED})...")
        results.append(run_scale(n))

    _SCALE_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(_SCALE_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=HEADER)
        w.writeheader()
        for r in results:
            w.writerow(r)

    # 1. Full table
    print("\n=== results/sim_scale.csv ===")
    print(f"{'N':>6} {'med_hops':>8} {'route_hops':>10} {'p50':>8} {'p95':>8} {'p99':>8} "
          f"{'thru_qps':>9} {'msg/node/s':>11} {'ring_msgs':>10}")
    for r in results:
        print(f"{r['n']:>6} {r['median_hops']:>8g} {r['mean_route_hops']:>10.2f} "
              f"{r['p50_ms']:>8.1f} {r['p95_ms']:>8.1f} {r['p99_ms']:>8.1f} "
              f"{r['throughput_qps']:>9.1f} {r['msgs_per_node_per_s']:>11.3f} "
              f"{r['total_ring_messages']:>10}")

    # 2. Hops vs theory (½·log₂N), on the routing path
    print("\n=== hop counts vs theory (routing path) ===")
    print(f"{'N':>6} {'expected ½·log₂N':>16} {'measured':>9} {'diff':>7}")
    for r in results:
        theory = 0.5 * math.log2(r["n"])
        meas = r["mean_route_hops"]
        print(f"{r['n']:>6} {theory:>16.2f} {meas:>9.2f} {meas - theory:>+7.2f}")

    print(f"\nwrote {_SCALE_CSV.relative_to(_HERE.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
