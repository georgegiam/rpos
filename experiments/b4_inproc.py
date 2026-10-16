#!/usr/bin/env python3
"""Issue #45 [B4] — Routing / eclipse, in-process ring (fast + robust; no 32-container Docker).

WHY THIS EXISTS — and why it is the PRIMARY (not a fallback as in B3). B4's question is routing:
"if f nodes run MALICIOUS_MODE=misroute (node/malicious.py claims successor-of-everything and bounces
the querier back to itself), how often is a lookup eclipsed — forced off the DHT onto fallback — and
at what extra hop cost?" Unlike B3's `drop` (which black-holes RPCs and STALLS the in-process
transport on 2 s timeouts, forcing B3 to isolate the storage read), `misroute` replies FAST and the
iterative walk `nxt == n` early-exits, so there is NO stall: the REAL end-to-end
node/query.py::resolve_query path (real find_successor -> wrong owner -> wrong replica_set ->
get_chunk None -> fallback) runs cleanly in-process. So B4's in-process run measures real hops and
real outcomes from the live node code — a MORE faithful vehicle than B3's reconstruction, not a
retreat from the testbed. (The optional socket cross-check, experiments/run_b4.sh +
experiments/b4_eclipse.py, anchors realistic-network latency.)

REAL RING IS AUTHORITATIVE. Routing depends on finger tables, which converge to — but are not bit-
identical to — the ideal fingers the host-side analytic model (experiments/b4_placement.py) builds;
on short lookups that small gap flips an eclipse decision. So this run derives BOTH the measured
eclipse (real resolve_query) AND the structural bound / targeted attacker selection from the LIVE
converged ring's own routing state (real_walk / real_path replay node.chord's find_successor against
nodes[i].successor()/closest_preceding, with misroute's only live primitive — closest_preceding ->
self — modelled exactly). The analytic model remains the host-side reference for the socket run and
the i.i.d. bound curve. node ids match the emulation (node.tests.util.pk_for == b1_placement._pk_for).

METHOD (isolates the attack from Chord-convergence noise, per the epic's cross-cutting rule):
  1. build + converge + POPULATE the DHT with ALL-HONEST nodes, and SNAPSHOT each node's store;
  2. for each point, RESTORE the pristine store + clear caches, flip f nodes to `misroute`, run the
     real resolve_query from the honest entry node 0 over a Zipf sample — reading the real
     (outcome, hops). Flipping AFTER convergence is essential: misroute during the build would poison
     joins/fix_fingers and conflate the read-path attack with chord.py fragility (that
     join/maintenance attack is distinct future work, see B4_NOTES.md);
  3. raw-DHT success = dht/(dht+fallback) (headline; eclipse rate = its complement = fallback-forced
     fraction); end-to-end stays ~100% because fallback recovers (harm = extra hops/latency).

The f=0 point is the HONEST CONTROL by construction (empty misrouter set -> 0% eclipse). Seeded
throughout (CLAUDE.md §2).

Run where dnspython is importable — the rpos-node image, or a local venv with it:
    python experiments/b4_inproc.py --queries 2000 --seeds 3
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

import node.query as _query                                      # noqa: E402
import node.malicious as _malicious                              # noqa: E402
# The measurement reads resolve_query's RETURN value, not the CSV; silence the per-query queries.csv
# append AND the per-misroute malicious.csv append (together millions of rows of pure noise) so the run
# is fast and leaves no litter.
_query.append_row = lambda *a, **k: None                        # noqa: E731
_malicious.append_row = lambda *a, **k: None                    # noqa: E731

from node.net import Network                                     # noqa: E402
from node.malicious import MaliciousNode                         # noqa: E402
from node.query import IterativeResolver                         # noqa: E402
from node.ids import chunk_id, in_interval                       # noqa: E402
from node.tests.util import build_ring                           # noqa: E402
from experiments import b4_placement as b4                       # noqa: E402
from experiments.b3_censorship import _mean_sd                   # noqa: E402 (shared stat)

N = 32
S = 3
PLOT_N = 1024            # frozen (PARAMETERS.md); small => fast in-process admission
SEED = 20260919
ALPHA = 1.0
F_LEVELS = [0, 10, 20, 30, 40, 50]
MANIFEST = REPO_ROOT / "testbed" / "dns" / "zones" / "MANIFEST.json"
OUT_CSV = REPO_ROOT / "results" / "B4_eclipse.csv"


def load_zone() -> dict[str, str]:
    recs = json.loads(MANIFEST.read_text())["records"]
    return {d: r["answer_ip"] for d, r in recs.items()}


def zipf_sample(domains: list[str], alpha: float, m: int, seed: int) -> list[str]:
    """m domains Zipf(alpha) over the popularity-ranked list (rank 1 = most popular), matching
    testbed/query_gen.py's weighting (popular, hence popular-eclipsed, chunks dominate — as in B1/B3)."""
    weights = [1.0 / ((i + 1) ** alpha) for i in range(len(domains))]
    return random.Random(seed).choices(domains, weights=weights, k=m)


# --------------------------------------------------------------------------------------------
# Real-ring routing replay (authoritative). These read the LIVE converged state (nodes[i].successor()
# / .closest_preceding — real fingers + successor list) and apply misroute's only live primitive:
# a misrouter's closest_preceding returns itself, so the honest walk's `nxt == n` fires and the walk
# returns that node's real successor = the wrong owner. ``get_successor`` is NOT overridden, so a
# misrouter still resolves a key that lies in its own successor interval (checked first) — exactly as
# node/chord.py::find_successor behaves against the real MaliciousNode over the bus.
# --------------------------------------------------------------------------------------------
def real_walk(nodes, id2idx, origin_id: int, key: int, mal_ids: set[int]) -> tuple[int, int]:
    n = origin_id
    hops = 0
    while True:
        node_n = nodes[id2idx[n]]
        n_succ = node_n.successor()
        if in_interval(key, n, n_succ, inc_right=True) or n == n_succ:
            return n_succ, hops
        if n in mal_ids:
            return n_succ, hops
        nxt = node_n.closest_preceding(key)
        if nxt == n:
            return n_succ, hops
        n = nxt
        hops += 1
        if hops > b4._SAFETY:
            return n_succ, hops


def real_path(nodes, id2idx, origin_id: int, key: int) -> list[int]:
    n = origin_id
    path = [n]
    hops = 0
    while True:
        node_n = nodes[id2idx[n]]
        n_succ = node_n.successor()
        if in_interval(key, n, n_succ, inc_right=True) or n == n_succ:
            return path
        nxt = node_n.closest_preceding(key)
        if nxt == n:
            return path
        n = nxt
        path.append(n)
        hops += 1
        if hops > b4._SAFETY:
            return path


def replica_set_ids(nodes, id2idx, primary_id: int, s: int) -> list[int]:
    """[primary] + primary's successor-list ids, truncated to s (mirrors node/storage.py::replica_set;
    the misrouter's get_succ_list is NOT overridden, so this is the real list the read would use)."""
    reps = [primary_id]
    for nid in nodes[id2idx[primary_id]].successor_list:
        if nid not in reps:
            reps.append(nid)
        if len(reps) >= s:
            break
    return reps[:s]


def real_dht_eclipse(nodes, idx2id, id2idx, origin_id: int, key: int,
                     mal_ids: set[int], s: int) -> bool:
    """True iff the misrouted lookup actually DENIES the chunk's DHT read — i.e. NO node in the
    misrouted primary's replica set holds the chunk (the exact condition node/storage.py::get_chunk
    returns None on). This is STRONGER than routing-eclipse: a wrong primary near the true owner shares
    successors with the real replica set, so the s-replica read still finds the chunk — replication
    rescues routing eclipse, the mirror of B3's majority-vote rescue of censorship."""
    primary, _ = real_walk(nodes, id2idx, origin_id, key, mal_ids)
    reps = replica_set_ids(nodes, id2idx, primary, s)
    return not any(key in nodes[id2idx[r]].store for r in reps)


def real_eclipse_fractions(nodes, idx2id, id2idx, ring, mal_idx, domains, s) -> tuple[float, float]:
    """(routing_eclipsed_pct, dht_denied_pct) over all served chunks under this placement:
    routing = lands on the wrong owner; dht_denied = the s-replica read finds nothing (the real harm,
    == the measured headline). Their GAP is the fraction rescued by replication's successor overlap."""
    origin = idx2id[0]
    mal_ids = {idx2id[i] for i in mal_idx}
    if not mal_ids or not domains:
        return 0.0, 0.0
    routing = denied = 0
    for d in domains:
        key = chunk_id(d)
        owner, _ = real_walk(nodes, id2idx, origin, key, mal_ids)
        if owner != ring.successor_of(key):
            routing += 1
        if real_dht_eclipse(nodes, idx2id, id2idx, origin, key, mal_ids, s):
            denied += 1
    n = len(domains)
    return 100.0 * routing / n, 100.0 * denied / n


def victim_node_attacker(nodes, idx2id, id2idx, ring, domains) -> tuple[int, int, list[str]]:
    """Auto victim = max-ownership non-anchor node; attacker = the single most-common first useful
    on-path hop toward its chunks (real ring). Returns (attacker_idx, victim_idx, victim_domains)."""
    origin = idx2id[0]
    owners = Counter(id2idx[ring.successor_of(chunk_id(d))] for d in domains)
    victim_idx = next(i for i, _ in owners.most_common() if i != 0)
    victim_id = idx2id[victim_idx]
    pred_id = ring.ids[(ring.pos[victim_id] - 1) % ring.n]
    forbidden = {origin, victim_id, pred_id}
    targets = [d for d in domains if ring.successor_of(chunk_id(d)) == victim_id]
    fh: Counter = Counter()
    for d in targets:
        for node in real_path(nodes, id2idx, origin, chunk_id(d))[1:]:
            if node not in forbidden:
                fh[node] += 1
                break
    attacker_id = fh.most_common(1)[0][0]
    return id2idx[attacker_id], victim_idx, targets


def victim_chunk_attacker(nodes, idx2id, id2idx, ring, domains, s) -> tuple[int, str]:
    """Pick the most popular served domain that a SINGLE misrouter actually DENIES (DHT read finds
    nothing) in the live ring — not merely routing-eclipses it (replication rescues most of those).
    Returns (attacker_idx, domain). Raises if none is single-misrouter-deniable."""
    origin = idx2id[0]
    for d in domains:                                   # popularity order
        key = chunk_id(d)
        owner = ring.successor_of(key)
        pred_id = ring.ids[(ring.pos[owner] - 1) % ring.n]
        forbidden = {origin, owner, pred_id}
        hop = next((node for node in real_path(nodes, id2idx, origin, key)[1:]
                    if node not in forbidden), None)
        if hop is None:
            continue
        if real_dht_eclipse(nodes, idx2id, id2idx, origin, key, {hop}, s):   # verify real DENIAL
            return id2idx[hop], d
    raise ValueError("no popular domain is single-misrouter-deniable (unexpected)")


async def build_ring_and_populate(domains: list[str], zone: dict[str, str]):
    """Build an all-honest in-process ring, populate the DHT, and snapshot each node's store."""
    net = Network()
    upstream = IterativeResolver(zone, ttl=0)        # cold path (no cache retention -> every query hits DHT)
    nodes = await build_ring(MaliciousNode, net, N, upstream=upstream, plot_n=PLOT_N, seed=SEED)
    for d in domains:                                 # one honest fallback+store per domain
        await nodes[0].resolve_query(d)
    snapshot = [dict(nd.store) for nd in nodes]       # pristine populated state
    return net, nodes, snapshot


def reset_point(nodes, snapshot, mal_idx: set[int]) -> None:
    """Restore the pristine DHT + clear caches, then flip exactly `mal_idx` to misroute (rest honest).

    Independent points (no fallback-write carryover): a previous point's fallback store_chunk writes
    the correct ip onto the WRONG (misrouted) nodes, which could later masquerade as a DHT hit — the
    restore removes that contamination so each f is measured on the same clean ring.
    """
    for i, nd in enumerate(nodes):
        nd.store = dict(snapshot[i])
        nd.cache = {}
        nd.malicious_mode = "misroute" if i in mal_idx else "honest"


async def measure_point(nodes, sample: list[str]) -> dict:
    """Run the REAL resolve_query from node 0 over `sample`; aggregate real (outcome, hops)."""
    dht = fb = cache = ok = 0
    dht_hops: list[int] = []
    fb_hops: list[int] = []
    all_hops: list[int] = []
    for d in sample:
        ip, _ttl, outcome, hops, _vote = await nodes[0].resolve_query(d)
        ok += int(ip is not None)
        all_hops.append(hops)
        if outcome == "dht_hit":
            dht += 1; dht_hops.append(hops)
        elif outcome == "fallback":
            fb += 1; fb_hops.append(hops)
        else:                                          # cache_hit (should not occur at ttl=0)
            cache += 1
    looked = dht + fb
    nan = float("nan")
    return {
        "raw_dht_success_pct": 100.0 * dht / looked if looked else nan,
        "eclipse_rate_pct": 100.0 * fb / looked if looked else nan,
        "e2e_success_pct": 100.0 * ok / len(sample) if sample else nan,
        "dht_pct": 100.0 * dht / len(sample) if sample else nan,
        "fallback_pct": 100.0 * fb / len(sample) if sample else nan,
        "mean_hops": statistics.fmean(all_hops) if all_hops else nan,
        "mean_hops_dht": statistics.fmean(dht_hops) if dht_hops else nan,
        "mean_hops_eclipsed": statistics.fmean(fb_hops) if fb_hops else nan,
    }


FIELDS = ["source", "block", "f_pct", "n_mal", "realized_f_pct", "runs",
          "raw_dht_success_pct", "raw_dht_success_sd",
          "eclipse_rate_pct", "eclipse_rate_sd",
          "e2e_success_pct", "e2e_success_sd",
          "bound_eclipsed_pct", "routing_eclipsed_pct", "structural_eclipsed_pct",
          "dht_pct", "fallback_pct",
          "mean_hops", "mean_hops_honest_dht", "mean_hops_eclipsed",
          "extra_hops", "extra_hops_delta_vs_f0",
          "target", "target_eclipse_rate_pct", "target_raw_dht_success_pct",
          "target_e2e_success_pct", "note"]


def _fmt(v) -> str:
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.4f}"
    return str(v)


async def run(args) -> int:
    zone = load_zone()
    domains = b4.load_served_domains()
    ring, idx2id, id2idx = b4.build_routing_ring(N, S)      # for successor_of ground truth + pos/ids
    L = b4.honest_mean_hops(N, S, domains)
    print(f"[b4-inproc] N={N} s={S} plot_n={PLOT_N} served={len(domains)} "
          f"queries/point={args.queries} seeds={args.seeds} honest-L̄={L:.3f}")
    print("[b4-inproc] building + populating the in-process ring (all honest)...")
    t0 = time.monotonic()
    net, nodes, snapshot = await build_ring_and_populate(domains, zone)
    # live-ring id maps (must match the analytic ids — same pk_for — but read from the real nodes)
    ridx2id = {i: nodes[i].node_id for i in range(N)}
    rid2idx = {v: k for k, v in ridx2id.items()}
    print(f"[b4-inproc] ring ready + DHT populated in {time.monotonic() - t0:.1f}s")

    rows: list[dict] = []
    baseline_dht_hops = float("nan")      # honest control (f=0) mean DHT hops
    for f_pct in (args.f_levels or F_LEVELS):
        n_mal = round(f_pct / 100 * N)
        realized_f = n_mal / N
        per, routs, structs = [], [], []
        for r in range(args.seeds):
            idx = b4.random_indices(N, n_mal, SEED + r) if n_mal else []
            reset_point(nodes, snapshot, set(idx))       # pristine stores before structural + measure
            rout_pct, denied_pct = real_eclipse_fractions(nodes, ridx2id, rid2idx, ring, idx, domains, S)
            routs.append(rout_pct); structs.append(denied_pct)
            sample = zipf_sample(domains, ALPHA, args.queries, SEED + 1000 * r + f_pct)
            per.append(await measure_point(nodes, sample))
        raw_m, raw_sd = _mean_sd([p["raw_dht_success_pct"] for p in per])
        ecl_m, ecl_sd = _mean_sd([p["eclipse_rate_pct"] for p in per])
        e2e_m, e2e_sd = _mean_sd([p["e2e_success_pct"] for p in per])
        mh_dht = _mean_sd([p["mean_hops_dht"] for p in per])[0]
        ecl_vals = [p["mean_hops_eclipsed"] for p in per if not math.isnan(p["mean_hops_eclipsed"])]
        mh_ecl = statistics.fmean(ecl_vals) if ecl_vals else float("nan")
        if f_pct == 0:
            baseline_dht_hops = mh_dht
        extra_within = mh_ecl - mh_dht if not math.isnan(mh_ecl) else float("nan")
        extra_vs_f0 = mh_ecl - baseline_dht_hops if not math.isnan(mh_ecl) else float("nan")
        rows.append({
            "source": "inproc", "block": "random", "f_pct": f_pct, "n_mal": n_mal,
            "realized_f_pct": 100.0 * realized_f, "runs": len(per),
            "raw_dht_success_pct": raw_m, "raw_dht_success_sd": raw_sd,
            "eclipse_rate_pct": ecl_m, "eclipse_rate_sd": ecl_sd,
            "e2e_success_pct": e2e_m, "e2e_success_sd": e2e_sd,
            "bound_eclipsed_pct": 100.0 * b4.eclipse_bound(realized_f, L),
            "routing_eclipsed_pct": _mean_sd(routs)[0],
            "structural_eclipsed_pct": _mean_sd(structs)[0],
            "dht_pct": _mean_sd([p["dht_pct"] for p in per])[0],
            "fallback_pct": _mean_sd([p["fallback_pct"] for p in per])[0],
            "mean_hops": _mean_sd([p["mean_hops"] for p in per])[0],
            "mean_hops_honest_dht": baseline_dht_hops,
            "mean_hops_eclipsed": mh_ecl,
            "extra_hops": extra_within,
            "extra_hops_delta_vs_f0": extra_vs_f0,
            "target": "", "target_eclipse_rate_pct": float("nan"),
            "target_raw_dht_success_pct": float("nan"), "target_e2e_success_pct": float("nan"),
            "note": "honest control" if f_pct == 0 else "",
        })
        print(f"  [random f={f_pct:>2}% n_mal={n_mal:>2}] eclipse={ecl_m:6.2f}% "
              f"(raw-DHT {raw_m:6.2f}%, routing-ecl {rows[-1]['routing_eclipsed_pct']:6.2f}% "
              f"-> DHT-denied {rows[-1]['structural_eclipsed_pct']:6.2f}%) "
              f"e2e={e2e_m:5.1f}% extra-hops(Δvs f0)={extra_vs_f0:.2f}")

    # targeted block: one misrouter isolates a victim NODE's whole key range (+ a victim-CHUNK variant)
    if not args.no_targeted:
        # select attackers from the REAL ring (same every run — deterministic topology)
        att_node, victim_idx, vtargets = victim_node_attacker(nodes, ridx2id, rid2idx, ring, domains)
        att_chunk, vchunk = victim_chunk_attacker(nodes, ridx2id, rid2idx, ring, domains, S)
        blocks = [
            ("targeted_node", [att_node], vtargets, f"node#{victim_idx}({len(vtargets)} chunks)"),
            ("targeted_chunk", [att_chunk], [vchunk], vchunk),
        ]
        for block, mal, targets, label in blocks:
            raws, e2es, ecls = [], [], []
            for _r in range(args.target_runs):
                reset_point(nodes, snapshot, set(mal))
                m = await measure_point(nodes, targets)
                raws.append(m["raw_dht_success_pct"]); e2es.append(m["e2e_success_pct"])
                ecls.append(m["eclipse_rate_pct"])
            n_mal = 1
            realized_f = n_mal / N
            rows.append({
                "source": "inproc", "block": block,
                "f_pct": round(100 * realized_f, 4), "n_mal": n_mal,
                "realized_f_pct": 100.0 * realized_f, "runs": args.target_runs,
                "raw_dht_success_pct": float("nan"), "raw_dht_success_sd": 0.0,
                "eclipse_rate_pct": float("nan"), "eclipse_rate_sd": 0.0,
                "e2e_success_pct": float("nan"), "e2e_success_sd": 0.0,
                "bound_eclipsed_pct": float("nan"), "routing_eclipsed_pct": float("nan"),
                "structural_eclipsed_pct": float("nan"),
                "dht_pct": float("nan"), "fallback_pct": float("nan"),
                "mean_hops": float("nan"), "mean_hops_honest_dht": baseline_dht_hops,
                "mean_hops_eclipsed": float("nan"),
                "extra_hops": float("nan"), "extra_hops_delta_vs_f0": float("nan"),
                "target": label,
                "target_eclipse_rate_pct": _mean_sd(ecls)[0],
                "target_raw_dht_success_pct": _mean_sd(raws)[0],
                "target_e2e_success_pct": _mean_sd(e2es)[0],
                "note": f"one misrouter (idx {mal[0]}) eclipses a victim "
                        f"{block.split('_')[1]}'s range (DHT denied, fallback recovers)",
            })
            print(f"  [targeted {block.split('_')[1]} target={label} attacker={mal[0]}] "
                  f"eclipse={rows[-1]['target_eclipse_rate_pct']:.1f}% "
                  f"raw-DHT={rows[-1]['target_raw_dht_success_pct']:.1f}% "
                  f"e2e={rows[-1]['target_e2e_success_pct']:.1f}%")

    for nd in nodes:
        nd.stop()

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\n[b4-inproc] wrote {OUT_CSV.relative_to(REPO_ROOT)} ({len(rows)} rows)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="B4 routing/eclipse — in-process real-ring run (issue #45).")
    ap.add_argument("--queries", type=int, default=2000, help="measured queries per point (per seed)")
    ap.add_argument("--seeds", type=int, default=3, help="independent random placements per f")
    ap.add_argument("--f-levels", type=int, nargs="*", default=None, help="override f%% levels")
    ap.add_argument("--no-targeted", action="store_true")
    ap.add_argument("--target-runs", type=int, default=3)
    args = ap.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
