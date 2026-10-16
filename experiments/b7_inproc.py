#!/usr/bin/env python3
"""Issue #48 [B7] — DoS flood, in-process mechanism complement (Phase 7, examiner point (ii)).

WHAT THIS IS (and is NOT). The B7 headline numbers come from the socket/Docker testbed
(experiments/run_b7.sh + b7_dos.py) because a resource-exhaustion flood is a REAL-TRANSPORT
phenomenon. This in-process run is the fast, reproducible MECHANISM complement: it shows the
chord.py fragility cascade — a flood congests the shared medium, honest maintenance RPCs
(stabilize's get_predecessor, timeout 2 s) start timing out, and chord.py drops a successor on ANY
RPC timeout, so the ring sheds good successors — WITHOUT a ~90-minute 32-container run, and it
produces the CI self-test.

THE IN-PROCESS ANALOG OF TRANSPORT CONGESTION. node/net.py is a single-event-loop asyncio bus;
each node's inbox is served SERIALLY. There is no TCP/netem cost to exhaust, so rate alone cannot
congest it the way sockets congest — the HONEST analog of the shared transport is the shared EVENT
LOOP. So "intensity" here is flood CONCURRENCY C: C open-loop workers keep ~C RPCs in flight,
saturating the loop and the victims' serve loops, which starves the probe's and the maintenance
driver's coroutines exactly as a socket flood starves the real transport. A small per-hop bus
latency makes that backlog translate into wall-clock delay (a documented stand-in for netem; the
socket run carries the real latency).

THE MANDATORY HONEST-CONTROL (epic cross-cutting rule). Each intensity is run TWICE at matched
volume:
  * arm=attack  — flood of find_successor on RANDOM keys (each forces a full iterative lookup);
  * arm=control — the SAME concurrency of find_successor on REAL served-chunk keys (what a heavy
                  but HONEST client issues). "Same traffic volume, honest sources."
protocol_delta_pct = control honest-success − attack honest-success at matched C: the part of the
degradation ATTRIBUTABLE to the adversary rather than to chord.py's load fragility (the whole point
of B7). The expectation (measured, not asserted): the delta is modest — most of the hit is
fragility, visible in ring_correct_succ_pct falling under load in BOTH arms.

Run where node.* is importable (dnspython needed by the node stack):
    python experiments/b7_inproc.py                 # full sweep -> results/b7/B7_inproc.csv
    python experiments/b7_inproc.py --self-test     # fast, asserts flood > no-flood degradation
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import math
import random
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import node.query as _query                                      # noqa: E402
import node.malicious as _malicious                              # noqa: E402
# The measurement reads resolve_query's RETURN value, not the CSV; silence per-query/per-event
# appends (noise + slow) exactly as b4_inproc does.
_query.append_row = lambda *a, **k: None                        # noqa: E731
_malicious.append_row = lambda *a, **k: None                    # noqa: E731

from node.net import Network                                     # noqa: E402
from node.malicious import MaliciousNode                         # noqa: E402
from node.query import IterativeResolver                         # noqa: E402
from node.ids import chunk_id, RING_SIZE, node_id_from_pk        # noqa: E402
from node.tests.util import build_ring                           # noqa: E402
from experiments.b3_censorship import _mean_sd, _pcts            # noqa: E402 (shared stats)
from experiments import b7_placement as b7p                      # noqa: E402

N = 32
S = 3
PLOT_N = 1024                 # frozen (PARAMETERS.md); small => fast in-process admission
SEED = 20260919
ALPHA = 1.0
BUS_LATENCY = 0.002           # per-hop stand-in so backlog -> wall-clock (netem is on the socket run)
PROBE_QPS = 10                # frozen measured load (PARAMETERS.md)
INTENSITIES = [0, 50, 100, 200, 400]     # flood concurrency C (in-flight RPCs)
FLOODER_ID = node_id_from_pk(b"b7-inproc-flooder")

MANIFEST = REPO_ROOT / "testbed" / "dns" / "zones" / "MANIFEST.json"
OUT_CSV = REPO_ROOT / "results" / "b7" / "B7_inproc.csv"

FIELDS = ["source", "block", "axis", "intensity", "f_pct", "n_mal", "realized_f_pct", "runs",
          "arm", "honest_success_pct", "honest_success_sd", "p50_ms", "p95_ms", "p99_ms",
          "offered_rpc_per_s", "measured_rpc_per_s", "ring_correct_succ_pct", "ring_orphans",
          "protocol_delta_pct", "note"]


def _fmt(v) -> str:
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.4f}"
    return str(v)


def load_zone() -> dict[str, str]:
    recs = json.loads(MANIFEST.read_text())["records"]
    return {d: r["answer_ip"] for d, r in recs.items()}


def zipf_sample(domains: list[str], alpha: float, m: int, seed: int) -> list[str]:
    weights = [1.0 / ((i + 1) ** alpha) for i in range(len(domains))]
    return random.Random(seed).choices(domains, weights=weights, k=m)


async def build_ring_and_populate(domains, zone):
    """All-honest in-process ring with a small bus latency, DHT populated, store snapshotted."""
    net = Network(latency=BUS_LATENCY)
    upstream = IterativeResolver(zone, ttl=0)        # cold path -> every probe query hits the DHT
    nodes = await build_ring(MaliciousNode, net, N, upstream=upstream, plot_n=PLOT_N, seed=SEED)
    for d in domains:
        await nodes[0].resolve_query(d)
    snapshot = [dict(nd.store) for nd in nodes]
    return net, nodes, snapshot


def reset(nodes, snapshot) -> None:
    """Restore the pristine populated DHT + clear caches; all nodes honest (the flood is external)."""
    for i, nd in enumerate(nodes):
        nd.store = dict(snapshot[i])
        nd.cache = {}
        nd.malicious_mode = "honest"


def ring_health(nodes) -> tuple[float, int]:
    """(% nodes whose immediate successor is the true ring-next, orphan count). Mirrors the socket
    finger_probe metric and node.tests.util.ring_is_consistent."""
    live = sorted(nd.node_id for nd in nodes if nd.alive)
    correct = orphans = 0
    for nd in nodes:
        if not nd.alive:
            continue
        idx = live.index(nd.node_id)
        true_succ = live[(idx + 1) % len(live)]
        if nd.successor() == true_succ:
            correct += 1
        else:
            orphans += 1
    return 100.0 * correct / len(live), orphans


async def _flood_worker(net, victim_ids, pattern, keys, rng, stop, counter) -> None:
    """Open-loop: immediately re-issue so ~1 RPC per worker stays in flight (concurrency = #workers)."""
    ti = ki = 0
    while time.monotonic() < stop:
        dst = victim_ids[ti % len(victim_ids)]; ti += 1
        if pattern == "junk":
            key = rng.getrandbits(160) % RING_SIZE
        else:
            key = keys[ki % len(keys)]; ki += 1
        try:
            await net.rpc(FLOODER_ID, dst, "find_successor", key, timeout=2.0)
        except Exception:
            pass
        counter[0] += 1


async def _maintenance(nodes, stop) -> None:
    """A light maintenance driver (the socket run's run_ring_node loop analog): stabilize +
    check_predecessor every ~1 s, each on chord.py's own 2 s RPC timeout — so under flood these
    time out and chord.py sheds successors (the fragility B7 probes)."""
    while time.monotonic() < stop:
        for nd in nodes:
            if not nd.alive:
                continue
            try:
                await nd.stabilize()
                await nd.check_predecessor()
            except Exception:
                pass
        await asyncio.sleep(1.0)


async def _probe(nodes, sample, stop) -> tuple[list[float], int, int]:
    """Honest probe: resolve_query from node 0 at PROBE_QPS, OPEN-LOOP (each query is its own task,
    like query_gen's thread pool) so a slow query under flood does not starve the sampling —
    sample count stays ~PROBE_QPS*duration regardless of latency. Collect (latencies, ok, total)."""
    async def one(d: str) -> tuple[float, bool]:
        t = time.perf_counter()
        try:
            ip, *_ = await asyncio.wait_for(nodes[0].resolve_query(d), timeout=5.0)
            succ = ip is not None
        except Exception:
            succ = False
        return (time.perf_counter() - t) * 1000.0, succ

    tasks: list[asyncio.Task] = []
    i = 0
    interval = 1.0 / PROBE_QPS
    while time.monotonic() < stop:
        d = sample[i % len(sample)]; i += 1
        tasks.append(asyncio.create_task(one(d)))
        await asyncio.sleep(interval)
    res = await asyncio.gather(*tasks, return_exceptions=False)
    lats = [r[0] for r in res]
    ok = sum(1 for r in res if r[1])
    return lats, ok, len(res)


async def run_arm(net, nodes, snapshot, victim_ids, pattern, concurrency,
                  sample, keys, duration, seed) -> dict:
    """One (intensity, arm) point: flood + maintenance + probe concurrently for `duration`."""
    reset(nodes, snapshot)
    stop = time.monotonic() + duration
    counter = [0]
    tasks = []
    if concurrency > 0:
        tasks = [asyncio.create_task(
            _flood_worker(net, victim_ids, pattern, keys, random.Random(seed + w), stop, counter))
            for w in range(concurrency)]
    maint = asyncio.create_task(_maintenance(nodes, stop))
    lats, ok, tot = await _probe(nodes, sample, stop)
    for t in tasks:
        t.cancel()
    maint.cancel()
    await asyncio.gather(*tasks, maint, return_exceptions=True)
    elapsed = max(1e-6, duration)
    p50, p95, p99 = _pcts(lats)
    hc, orph = ring_health(nodes)
    return {
        "success": 100.0 * ok / tot if tot else float("nan"),
        "p50": p50, "p95": p95, "p99": p99,
        "measured_rpc_per_s": counter[0] / elapsed,
        "ring_correct_succ_pct": hc, "ring_orphans": orph,
    }


async def run(args) -> int:
    zone = load_zone()
    domains = b7p.load_served_domains()
    keys = [chunk_id(d) for d in domains]
    victims_idx = b7p.broad_targets(N)
    print(f"[b7-inproc] N={N} s={S} plot_n={PLOT_N} served={len(domains)} "
          f"intensities={args.intensities} seeds={args.seeds} dur={args.duration}s bus_lat={BUS_LATENCY}s")
    print("[b7-inproc] building + populating the in-process ring (all honest)...")
    t0 = time.monotonic()
    net, nodes, snapshot = await build_ring_and_populate(domains, zone)
    victim_ids = [nodes[i].node_id for i in victims_idx]
    print(f"[b7-inproc] ring ready + DHT populated in {time.monotonic() - t0:.1f}s")

    rows: list[dict] = []
    for C in args.intensities:
        per = {"attack": [], "control": []}
        for r in range(args.seeds):
            sample = zipf_sample(domains, ALPHA, 10_000, SEED + 1000 * r + C)
            for arm, pattern in (("attack", "junk"), ("control", "honest")):
                m = await run_arm(net, nodes, snapshot, victim_ids, pattern, C,
                                  sample, keys, args.duration, SEED + r)
                per[arm].append(m)
        agg = {}
        for arm in ("attack", "control"):
            succ_m, succ_sd = _mean_sd([m["success"] for m in per[arm]])
            agg[arm] = {
                "success": succ_m, "success_sd": succ_sd,
                "p50": _mean_sd([m["p50"] for m in per[arm]])[0],
                "p95": _mean_sd([m["p95"] for m in per[arm]])[0],
                "p99": _mean_sd([m["p99"] for m in per[arm]])[0],
                "rpc": _mean_sd([m["measured_rpc_per_s"] for m in per[arm]])[0],
                "hc": _mean_sd([m["ring_correct_succ_pct"] for m in per[arm]])[0],
                "orph": _mean_sd([float(m["ring_orphans"]) for m in per[arm]])[0],
            }
        delta = agg["control"]["success"] - agg["attack"]["success"]
        for arm in ("attack", "control"):
            a = agg[arm]
            rows.append({
                "source": "inproc", "block": "flood", "axis": "concurrency", "intensity": C,
                "f_pct": "", "n_mal": "", "realized_f_pct": "", "runs": args.seeds, "arm": arm,
                "honest_success_pct": a["success"], "honest_success_sd": a["success_sd"],
                "p50_ms": a["p50"], "p95_ms": a["p95"], "p99_ms": a["p99"],
                "offered_rpc_per_s": "", "measured_rpc_per_s": a["rpc"],
                "ring_correct_succ_pct": a["hc"], "ring_orphans": round(a["orph"], 2),
                "protocol_delta_pct": delta if arm == "attack" else float("nan"),
                "note": ("honest control (no flood)" if C == 0 and arm == "attack"
                         else ("matched-volume honest load" if arm == "control" else "")),
            })
        print(f"  C={C:>4}: attack succ={agg['attack']['success']:5.1f}% "
              f"p95={agg['attack']['p95']:7.1f}ms health={agg['attack']['hc']:5.1f}% | "
              f"control succ={agg['control']['success']:5.1f}% health={agg['control']['hc']:5.1f}% | "
              f"delta={delta:+.2f}pp")

    for nd in nodes:
        nd.stop()

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\n[b7-inproc] wrote {OUT_CSV.relative_to(REPO_ROOT)} ({len(rows)} rows)")
    return 0


def _self_test() -> int:
    """Fast: flood (C>0) must degrade the probe and/or ring health vs no-flood (C=0)."""
    async def go() -> bool:
        zone = load_zone()
        domains = b7p.load_served_domains()
        keys = [chunk_id(d) for d in domains]
        net, nodes, snapshot = await build_ring_and_populate(domains, zone)
        victim_ids = [nodes[i].node_id for i in b7p.broad_targets(N)]
        sample = zipf_sample(domains, ALPHA, 2000, SEED)
        base = await run_arm(net, nodes, snapshot, victim_ids, "junk", 0, sample, keys, 1.5, SEED)
        hi = await run_arm(net, nodes, snapshot, victim_ids, "junk", 200, sample, keys, 1.5, SEED)
        for nd in nodes:
            nd.stop()
        drove = hi["measured_rpc_per_s"] > 100.0
        # the flood must make the probe slower OR the ring less healthy (the mechanism)
        degraded = (hi["p95"] > base["p95"] + 1.0) or (hi["ring_correct_succ_pct"]
                                                       < base["ring_correct_succ_pct"] - 0.1) \
            or (hi["success"] < base["success"] - 0.1)
        print(f"  [self-test] C=0  : succ={base['success']:.1f}% p95={base['p95']:.1f}ms "
              f"health={base['ring_correct_succ_pct']:.1f}%")
        print(f"  [self-test] C=200: succ={hi['success']:.1f}% p95={hi['p95']:.1f}ms "
              f"health={hi['ring_correct_succ_pct']:.1f}% rpc={hi['measured_rpc_per_s']:.0f}/s")
        print(f"  [self-test] flood drove RPCs={drove} degraded-probe-or-ring={degraded}")
        return bool(drove and degraded)

    ok = asyncio.run(go())
    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="B7 DoS flood — in-process mechanism complement (issue #48).")
    ap.add_argument("--intensities", type=int, nargs="*", default=INTENSITIES,
                    help="flood concurrency levels C (in-flight RPCs)")
    ap.add_argument("--seeds", type=int, default=3, help="repeats per (intensity, arm)")
    ap.add_argument("--duration", type=float, default=6.0, help="seconds per (intensity, arm)")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    return asyncio.run(run(a))


if __name__ == "__main__":
    raise SystemExit(main())
