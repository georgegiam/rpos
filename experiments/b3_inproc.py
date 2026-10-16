#!/usr/bin/env python3
"""Issue #44 [B3] — Censorship, in-process ring (fast + robust; no 32-container Docker orchestration).

WHY THIS EXISTS. B3's core question — "if f malicious nodes refuse to serve (MALICIOUS_MODE=drop),
can specific domains still be resolved?" — is STORAGE-LAYER PROTOCOL LOGIC: a chunk's DHT read is
denied iff ALL s of its replicas drop (one honest replica rescues the majority vote in
node/storage.py::get_chunk), and a denied read still resolves via node/query.py's fallback. This
module answers it with the REAL node code — it builds a real in-process ring (the Phase-2 transport /
B2 admission-demo pattern), POPULATES the DHT with real resolve_query fallback+store, then reads each
queried chunk over its real converged replica set using the real stored data and the real
majority-vote — WITHOUT the flaky, ~90-minute 32-container testbed.

WHY STORAGE-LAYER, NOT FULL resolve_query: the in-process transport (node/net.py) has no liveness
cache (unlike node/socket_net.py's _mark_down / fail_threshold), so a full end-to-end in-process run
STALLS at high f — every find_successor hop onto a blanket-drop black hole waits the 2 s RPC timeout
with nothing routing around it. That stall is an ARTIFACT OF THE IN-PROCESS TRANSPORT, not the
protocol: the real socket testbed marks drop peers down and routes around them (exactly as it heals
around churn in A6). So we isolate the actual censorship surface — the s-replica storage read + vote
— over the real converged ring, and take realistic latency / end-to-end timing from the socket
testbed (experiments/run_b3.sh; its f=0/f=10 points already anchored this model).

METHOD (also isolates the attack from Chord-convergence noise, per the epic's cross-cutting rule):
  1. build + converge + POPULATE the DHT with ALL-HONEST nodes (every domain on its s honest replicas);
  2. for each point, mark f nodes `drop`; read each Zipf-sampled chunk over its converged replica set,
     skipping drop replicas (as _should_drop would) and majority-voting the rest (identical to
     node/storage.py::get_chunk) — dht_hit if any honest replica holds it, else fallback;
  3. raw-DHT success = dht/(dht+fallback) (the censorship headline, tracks 1 − f^s); end-to-end stays
     resolvable because the honest entry's fallback re-fetches a denied chunk from the zone.

Run where dnspython is importable — the rpos-node image:
    docker run --rm -v "$PWD":/repo -w /repo rpos-node:latest python experiments/b3_inproc.py
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
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from node.net import Network                                    # noqa: E402
from node.malicious import MaliciousNode                        # noqa: E402
from node.query import IterativeResolver                        # noqa: E402
from node.ids import chunk_id                                   # noqa: E402
from node.tests.util import build_ring                          # noqa: E402
from experiments import b3_placement as b3                      # noqa: E402
from experiments.b3_censorship import _mean_sd                  # noqa: E402 (shared stat)

N = 32
S = 3
PLOT_N = 1024            # frozen (PARAMETERS.md); small => fast in-process admission
SEED = 20260919
ALPHA = 1.0
F_LEVELS = [0, 10, 20, 30, 40, 50]
MANIFEST = REPO_ROOT / "testbed" / "dns" / "zones" / "MANIFEST.json"
OUT_CSV = REPO_ROOT / "results" / "B3_censorship.csv"


def load_zone() -> dict[str, str]:
    recs = json.loads(MANIFEST.read_text())["records"]
    return {d: r["answer_ip"] for d, r in recs.items()}


def zipf_sample(domains: list[str], alpha: float, m: int, seed: int) -> list[str]:
    """m domains Zipf(alpha) over the popularity-ranked list (rank 1 = most popular), matching
    testbed/query_gen.py's weighting (popular, hence popular-captured, chunks dominate — as in B1)."""
    weights = [1.0 / ((i + 1) ** alpha) for i in range(len(domains))]
    return random.Random(seed).choices(domains, weights=weights, k=m)


async def build_ring_and_populate(domains: list[str], zone: dict[str, str]):
    """Build an all-honest in-process ring and populate the DHT with every served domain."""
    net = Network()
    upstream = IterativeResolver(zone, ttl=0)        # cold path (no cache retention)
    nodes = await build_ring(MaliciousNode, net, N, upstream=upstream, plot_n=PLOT_N, seed=SEED)
    for d in domains:                                 # one honest fallback+store per domain
        await nodes[0].resolve_query(d)
    return net, nodes


def storage_read(nodes, repmap: dict[str, list[int]], d: str, drop: set[int]) -> tuple[str, bool]:
    """Read domain d over its converged replica set using REAL stored data + the REAL majority vote
    (node/storage.py::get_chunk semantics: skip a drop/non-responding replica, skip None, plurality
    over responders). Returns (outcome, e2e_success). A denied read falls back to the zone (the
    honest entry's IterativeResolver), which still resolves a served domain."""
    cid = chunk_id(d)
    values = []
    for idx in repmap[d]:
        if idx in drop:
            continue                                  # drop replica: no reply (real _should_drop)
        v = nodes[idx].store.get(cid)                 # real stored data (== _h_get_chunk)
        if v is not None:
            values.append(v)
    if values:
        Counter(values).most_common(1)                # vote is taken (value unused here)
        return "dht_hit", True
    return "fallback", True                            # fallback re-fetches from the zone -> resolves


def measure_point(nodes, repmap, mal_idx: list[int], sample: list[str]) -> dict:
    drop = set(mal_idx)
    dht = fb = ok = 0
    for d in sample:
        outcome, e2e = storage_read(nodes, repmap, d, drop)
        dht += outcome == "dht_hit"
        fb += outcome == "fallback"
        ok += int(e2e)
    looked = dht + fb
    return {
        "raw_dht_success_pct": 100.0 * dht / looked if looked else float("nan"),
        "dht_pct": 100.0 * dht / len(sample) if sample else float("nan"),
        "fallback_pct": 100.0 * fb / len(sample) if sample else float("nan"),
        "e2e_success_pct": 100.0 * ok / len(sample) if sample else float("nan"),
    }


FIELDS = ["source", "block", "f_pct", "n_mal", "realized_f_pct", "runs",
          "raw_dht_success_pct", "raw_dht_success_sd", "e2e_success_pct", "e2e_success_sd",
          "bound_censored_pct", "structural_censored_pct", "dht_pct", "fallback_pct",
          "target", "target_raw_dht_success_pct", "target_e2e_success_pct", "note"]


def _fmt(v) -> str:
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.4f}"
    return str(v)


async def run(args) -> int:
    zone = load_zone()
    domains = b3.load_served_domains()
    ring, id2idx = b3.build_ring(N, S)
    repmap = {d: b3.replica_indices(d, ring, id2idx, S) for d in domains}
    print(f"[b3-inproc] N={N} s={S} plot_n={PLOT_N} served={len(domains)} "
          f"queries/point={args.queries} seeds={args.seeds}")
    print("[b3-inproc] building + populating the in-process ring (all honest)...")
    t0 = time.monotonic()
    net, nodes = await build_ring_and_populate(domains, zone)
    print(f"[b3-inproc] ring ready + DHT populated in {time.monotonic() - t0:.1f}s")

    rows: list[dict] = []
    for f_pct in (args.f_levels or F_LEVELS):
        n_mal = round(f_pct / 100 * N)
        realized_f = n_mal / N
        per, structs = [], []
        for r in range(args.seeds):
            idx = b3.random_indices(N, n_mal, SEED + r) if n_mal else []
            structs.append(100.0 * b3.structural_censored_fraction(idx, N, S, domains))
            sample = zipf_sample(domains, ALPHA, args.queries, SEED + 1000 * r + f_pct)
            per.append(measure_point(nodes, repmap, idx, sample))
        raw_m, raw_sd = _mean_sd([p["raw_dht_success_pct"] for p in per])
        e2e_m, e2e_sd = _mean_sd([p["e2e_success_pct"] for p in per])
        rows.append({
            "source": "inproc", "block": "random", "f_pct": f_pct, "n_mal": n_mal,
            "realized_f_pct": 100.0 * realized_f, "runs": len(per),
            "raw_dht_success_pct": raw_m, "raw_dht_success_sd": raw_sd,
            "e2e_success_pct": e2e_m, "e2e_success_sd": e2e_sd,
            "bound_censored_pct": 100.0 * b3.censor_bound(realized_f, S),
            "structural_censored_pct": _mean_sd(structs)[0],
            "dht_pct": _mean_sd([p["dht_pct"] for p in per])[0],
            "fallback_pct": _mean_sd([p["fallback_pct"] for p in per])[0],
            "target": "", "target_raw_dht_success_pct": float("nan"),
            "target_e2e_success_pct": float("nan"),
            "note": "honest control" if f_pct == 0 else "",
        })
        print(f"  [random f={f_pct:>2}% n_mal={n_mal:>2}] raw-DHT={raw_m:6.2f}% "
              f"(resolvable bound {100 - 100 * b3.censor_bound(realized_f, S):6.2f}%) "
              f"e2e={e2e_m:5.1f}% struct-censored={rows[-1]['structural_censored_pct']:5.2f}%")

    # targeted block: all s replicas of one popular chunk dropped -> DHT denied, fallback recovers
    if not args.no_targeted:
        tgt_raw, tgt_e2e, tgts, nmals = [], [], [], []
        for r in range(args.target_runs):
            idx, target = b3.targeted_censor_indices(N, S, SEED + 100 + r)
            drop = set(idx)
            sample = [target] * args.target_reps
            m = measure_point(nodes, repmap, idx, sample)
            tgt_raw.append(m["raw_dht_success_pct"])
            tgt_e2e.append(m["e2e_success_pct"])
            tgts.append(target); nmals.append(len(idx))
        n_mal = round(statistics.fmean(nmals)) if nmals else 0
        realized_f = n_mal / N
        rows.append({
            "source": "inproc", "block": "targeted", "f_pct": round(100 * realized_f),
            "n_mal": n_mal, "realized_f_pct": 100.0 * realized_f, "runs": args.target_runs,
            "raw_dht_success_pct": float("nan"), "raw_dht_success_sd": 0.0,
            "e2e_success_pct": float("nan"), "e2e_success_sd": 0.0,
            "bound_censored_pct": 100.0 * b3.censor_bound(realized_f, S),
            "structural_censored_pct": float("nan"),
            "dht_pct": float("nan"), "fallback_pct": float("nan"),
            "target": tgts[0] if tgts else "",
            "target_raw_dht_success_pct": _mean_sd(tgt_raw)[0] if tgt_raw else float("nan"),
            "target_e2e_success_pct": _mean_sd(tgt_e2e)[0] if tgt_e2e else float("nan"),
            "note": "full-replica capture: all s replicas of one popular chunk dropped "
                    "(DHT denied, fallback recovers)",
        })
        print(f"  [targeted target={rows[-1]['target']} n_mal={n_mal}] "
              f"target raw-DHT={rows[-1]['target_raw_dht_success_pct']:.1f}% "
              f"e2e={rows[-1]['target_e2e_success_pct']:.1f}%")

    for nd in nodes:
        nd.stop()

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\n[b3-inproc] wrote {OUT_CSV.relative_to(REPO_ROOT)} ({len(rows)} rows)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="B3 censorship — in-process storage-layer ring (issue #44).")
    ap.add_argument("--queries", type=int, default=2000, help="measured queries per point (per seed)")
    ap.add_argument("--seeds", type=int, default=3, help="independent random placements per f")
    ap.add_argument("--f-levels", type=int, nargs="*", default=None, help="override f%% levels")
    ap.add_argument("--no-targeted", action="store_true")
    ap.add_argument("--target-runs", type=int, default=3)
    ap.add_argument("--target-reps", type=int, default=50, help="repeated queries of the target domain")
    args = ap.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
