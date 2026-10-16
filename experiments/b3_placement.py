#!/usr/bin/env python3
"""Issue #44 [B3] — malicious-node placement helper for the censorship run.

B3 makes a fraction ``f`` of the N=32 ring run in ``drop`` mode (node/malicious.py's
``_should_drop`` → a transport-level black hole that never replies to an inbound RPC) and measures
whether domains still resolve, and at what added latency, as f grows. A ``drop`` node answers no
``get_chunk_local`` / ``put_chunk_local`` / routing / maintenance RPC, so to the ring it reads like
a dead/eclipsed node that Chord heals around (cf. A6 churn). A chunk's DHT read is DENIED only when
**all s of its replicas drop** — a single honest replica still answers and the majority vote returns
it — so the censorship bound is ``f**s`` (contrast B1's ``1−(1−f)^s`` for integrity). Even a fully
censored chunk still resolves via the honest entry node's iterative-resolution fallback, so the
headline effect is on the **raw-DHT lookup success rate** (and latency), not end-to-end success.

This module is the DRIVER's placement brain (CLAUDE.md §2 — new code in a new file; it imports
read-only and touches no protocol / frozen artifact). It runs on the HOST before bring-up, so it
must NOT import testbed/query_gen.py (dnspython, absent on the host). It reuses B1's placement model
verbatim — node identities ``node_id_from_pk(_pk_for(i))`` and converged-ring replica sets from
``sim/chord_sim.ChordRing`` + ``sim/query_sim._replica_set`` — so everything is bit-for-bit
reconstructible from (N, s, seed). It prints the malicious index list for
``gen_nodes_compose.py --malicious-indices`` (via run_experiment.sh ``--malicious-mode drop``).

Two placement strategies:

  * random   — f*N nodes chosen uniformly from indices 1..N-1 (node 0, the seed/entry anchor, is
               never malicious). Over many chunks the fully-censored fraction tracks ``f**s`` (s=3).
  * targeted — co-locate drop on ALL s replicas of ONE popular target chunk, so that chunk's DHT
               read is denied regardless of the global f (the worst-case censorship demo; B1's
               targeted block captured only a majority — B3 needs the whole replica set to deny).

CLI (prints the malicious index list to stdout; optional JSON metadata to --out):

    python3 b3_placement.py --n 32 --s 3 --n-mal 6 --placement random --seed 20260919
    python3 b3_placement.py --placement targeted --seed 20260919 --out place.json
    python3 b3_placement.py --self-test
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# B3 reuses B1's placement model verbatim (same ring, ids, replica sets). Importing it (rather than
# copying) keeps the two experiments provably consistent and touches no frozen artifact.
from experiments.b1_placement import (  # noqa: E402
    DEFAULT_SEED, DEFAULT_N, DEFAULT_S,
    build_ring, replica_indices, random_indices, load_served_domains,
    structural_capture_fraction,
)


# --------------------------------------------------------------------------------------------
# Censorship bound + realized fraction (ALL s replicas must drop to deny a chunk's DHT read).
# --------------------------------------------------------------------------------------------
def censor_bound(f: float, s: int = DEFAULT_S) -> float:
    """P(a random chunk has ALL s replicas malicious) under i.i.d. random placement = f**s.

    This is the fraction of chunks whose DHT read is fully DENIED (returns None → fallback): the
    majority vote in node/storage.py::get_chunk tolerates any single honest replica, so one honest
    replica anywhere in the set rescues the read. Contrast B1's achieved integrity bound
    ``1−(1−f)^s`` (a SINGLE malicious replica forges), which is the opposite extreme — censorship is
    the HARDEST attack on this store, forgery the easiest.
    """
    return f ** s


def structural_censored_fraction(mal_set: list[int], n: int, s: int,
                                 domains: list[str] | None = None) -> float:
    """Realized censorship bound: fraction of served chunks whose replica set is ENTIRELY malicious.

    Computed over the ACTUAL seeded placement + real ring (thresh=s), so it is the bound this
    specific run should match (``f**s`` is the i.i.d. limit). Reuses B1's structural helper with
    threshold = s (all replicas), vs B1's majority / single thresholds.
    """
    return structural_capture_fraction(mal_set, n, s, domains, thresh=s)


# --------------------------------------------------------------------------------------------
# Targeted censorship: drop on ALL s replicas of one popular chunk.
# --------------------------------------------------------------------------------------------
def targeted_censor_indices(n: int, s: int, seed: int,
                            target: str | None = None) -> tuple[list[int], str]:
    """Make every one of a target chunk's s replicas a drop node, so its DHT read is always denied.

    Returns (indices, target_domain). Picks (when target is None/"auto") the most popular served
    domain whose replica set has s DISTINCT nodes and excludes node 0 (so only non-anchor nodes are
    corrupted and the honest entry can still fall back). Unlike B1's targeted_indices — which caps
    the co-located set at the majority threshold and spends any extra budget randomly — B3 corrupts
    the WHOLE replica set (budget == s), the minimum needed to actually deny the chunk's DHT path.
    """
    ring, id2idx = build_ring(n, s)
    domains = load_served_domains()

    if target and target != "auto":
        reps = replica_indices(target, ring, id2idx, s)
        if len(set(reps)) < s:
            raise ValueError(f"target {target!r} replica set {reps} has < s={s} distinct nodes")
        if 0 in reps:
            raise ValueError(f"target {target!r} has node 0 in its replica set {reps}; pick another")
        return sorted(set(reps)), target

    for d in domains:                                   # popularity order
        reps = replica_indices(d, ring, id2idx, s)
        if 0 not in reps and len(set(reps)) >= s:
            return sorted(set(reps)), d
    raise ValueError("no served domain has an s-distinct, node-0-free replica set (unexpected)")


# --------------------------------------------------------------------------------------------
# Self-test — the plan's verification step 1 (no Docker, deterministic).
# --------------------------------------------------------------------------------------------
def _self_test() -> int:
    n, s = DEFAULT_N, DEFAULT_S
    domains = load_served_domains()
    print(f"[self-test] N={n} s={s} served={len(domains)} censor-bound=f^{s}")

    ok = True
    # (a) random fully-censored fraction tracks f**s at each f (averaged over independent placements).
    for f_pct, n_mal in zip([0, 10, 20, 30, 40, 50], [0, 3, 6, 10, 13, 16]):
        f = n_mal / n
        vals = [structural_censored_fraction(random_indices(n, n_mal, DEFAULT_SEED + r), n, s, domains)
                for r in range(8)]
        measured = sum(vals) / len(vals)
        bound = censor_bound(f, s)
        tol = 0.02 + 0.30 * bound           # generous: f^s is tiny, finite ring + domain sample
        flag = "ok" if abs(measured - bound) <= tol else "OFF"
        if flag == "OFF":
            ok = False
        print(f"  f={f_pct:>2}% n_mal={n_mal:>2} realized f={f:.4f} "
              f"structural-censored={measured:.4f} bound f^{s}={bound:.4f}  [{flag}]")

    # (b) targeted placement denies its target: ALL s replicas malicious, node 0 free.
    mal, target = targeted_censor_indices(n, s, DEFAULT_SEED)
    ring, id2idx = build_ring(n, s)
    reps = replica_indices(target, ring, id2idx, s)
    all_dropped = set(reps) <= set(mal) and len(set(reps)) == s
    node0_free = 0 not in mal
    print(f"  targeted target={target!r} replicas={reps} malicious={mal} "
          f"all_dropped={all_dropped} node0_free={node0_free}")
    ok = ok and all_dropped and node0_free

    # (c) exactly the target chunk is fully censored by that minimal placement (others ~random).
    frac = structural_censored_fraction(mal, n, s, domains)
    print(f"  targeted global fully-censored fraction={frac:.4f} (>=1 chunk forced, rest ~random)")
    ok = ok and frac > 0.0

    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="B3 malicious-node (drop) placement (issue #44).")
    ap.add_argument("--n", type=int, default=DEFAULT_N, help="ring size N (default 32)")
    ap.add_argument("--s", type=int, default=DEFAULT_S, help="replication factor (default 3)")
    ap.add_argument("--n-mal", type=int, default=0, help="number of malicious nodes (random)")
    ap.add_argument("--placement", choices=["random", "targeted"], default="random")
    ap.add_argument("--target", default="auto",
                    help="targeted: domain to censor, or 'auto' (most popular node-0-free chunk)")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--out", type=Path, default=None,
                    help="also write JSON metadata (f_pct, n_mal, placement, indices, target) here")
    ap.add_argument("--self-test", action="store_true", help="run the deterministic self-test")
    a = ap.parse_args()

    if a.self_test:
        return _self_test()

    target = None
    if a.placement == "random":
        indices = random_indices(a.n, a.n_mal, a.seed)
    else:
        indices, target = targeted_censor_indices(a.n, a.s, a.seed, a.target)

    n_mal = len(indices)
    meta = {
        "n": a.n, "s": a.s, "placement": a.placement, "seed": a.seed, "mode": "drop",
        "n_mal": n_mal, "f_pct": round(100.0 * n_mal / a.n, 4),
        "indices": ",".join(str(i) for i in indices), "target": target,
    }
    if a.out is not None:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(meta, indent=2) + "\n")
    # stdout = just the index list, for shell capture (empty line when n_mal==0 → all honest).
    print(meta["indices"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
