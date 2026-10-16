#!/usr/bin/env python3
"""Issue #45 [B4] — malicious-node placement helper for the routing / eclipse run.

B4 makes a fraction ``f`` of the N=32 ring run in ``misroute`` mode (node/malicious.py's
``_h_find_successor`` / ``_h_closest_preceding`` overrides: the node claims to be the successor of
every key and, when asked for the closest preceding node, hands the querier back to ITSELF — so an
iterative lookup that reaches it terminates early at the WRONG successor). B4 measures how often a
lookup is eclipsed (forced off the DHT onto fallback) and the extra hops that costs, as f grows,
and whether a handful of misrouters can isolate a victim.

This module is the DRIVER's placement brain (CLAUDE.md §2 — new code in a new file; it imports
read-only and touches no protocol / frozen artifact). It runs on the HOST before bring-up, so it
must NOT import testbed/query_gen.py (dnspython, absent on the host). It reuses B1's placement model
verbatim — node identities ``node_id_from_pk(_pk_for(i))`` and the converged ring from
``sim/chord_sim.ChordRing`` — so everything is bit-for-bit reconstructible from (N, s, seed). It
prints the malicious index list for ``gen_nodes_compose.py --malicious-indices`` (via
run_experiment.sh ``--malicious-mode misroute``).

The routing model. Unlike B1/B3 (which only need replica *placement*), B4 needs the lookup *walk*,
so it builds the ring with fingers (``build_fingers=True``) and ports node/chord.py::find_successor
with the misroute override (``misroute_walk``). ``get_successor`` is NOT overridden by misroute, so a
misrouter still resolves a key that lies in its own successor interval — the attack bites only when
the walk must forward PAST the misrouter, which it then refuses to do (returns its own successor =
the wrong owner). This is the exact in-process behaviour b4_inproc.py measures with the real node
code; the two should agree to within convergence noise.

Two placement strategies:

  * random   — f*N nodes chosen uniformly from indices 1..N-1 (node 0, the seed/entry anchor, is
               never malicious). The realized eclipse fraction tracks the structural line below (and
               the i.i.d. reference 1−(1−f)^L̄, L̄ = honest mean hops). Note eclipse sits ABOVE f at
               low f — a few of node 0's fingers carry most lookups (finger-table centrality).
  * targeted — eclipse a victim NODE's ENTIRE key range from node 0 by corrupting the single first
               on-path hop toward it (one misrouter ≈ 100% of that node's chunks), or a victim CHUNK
               (``--victim-chunk``). The routing-layer analog of B3's targeted full-replica censor —
               but far cheaper (one node, not a whole replica set; see B2 for the grinding cost).

CLI (prints the malicious index list to stdout; optional JSON metadata to --out):

    python3 b4_placement.py --n 32 --s 3 --n-mal 6 --placement random --seed 20260919
    python3 b4_placement.py --placement targeted --seed 20260919 --out place.json
    python3 b4_placement.py --placement targeted --victim-chunk google.com --seed 20260919
    python3 b4_placement.py --self-test
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from node.ids import chunk_id, in_interval, RING_BITS           # noqa: E402 (hashlib-only, host-safe)
from sim.chord_sim import ChordRing                             # noqa: E402
from sim.query_sim import _replica_set                          # noqa: E402

# B4 reuses B1's placement model verbatim (same ring ids, same served domain set). Importing it
# (rather than copying) keeps the experiments provably consistent and touches no frozen artifact.
from experiments.b1_placement import (  # noqa: E402
    DEFAULT_SEED, DEFAULT_N, DEFAULT_S,
    index_to_id_map, random_indices, load_served_domains,
)


# --------------------------------------------------------------------------------------------
# A converged ring WITH fingers (B1/B3 build fingerless rings — only placement is needed there;
# B4 needs the multi-hop walk, so fingers must be present).
# --------------------------------------------------------------------------------------------
def build_routing_ring(n: int, s: int = DEFAULT_S):
    """Converged ChordRing over the real emulation ids, fingers built; returns (ring, id->index)."""
    idx2id = index_to_id_map(n)
    ring = ChordRing(
        0, ids=list(idx2id.values()), seed=DEFAULT_SEED,
        build_fingers=True,                        # B4 needs routing, not just placement
        succ_list_len=max(3, s - 1),               # mirrors A4 / storage.replica_set
    )
    id2idx = {v: k for k, v in idx2id.items()}
    return ring, idx2id, id2idx


_SAFETY = RING_BITS + DEFAULT_S + 4                 # transient-loop guard (matches chord.py)


# --------------------------------------------------------------------------------------------
# The lookup walk, honest and under misroute (exact port of node/chord.py::find_successor).
# --------------------------------------------------------------------------------------------
def honest_path(ring: ChordRing, origin_id: int, key: int) -> list[int]:
    """The ordered node ids an HONEST iterative lookup for ``key`` visits from ``origin_id``.

    Identical to ChordRing.route().path, repeated here so the targeted builder can inspect the
    on-path hops without constructing a RouteResult per chunk.
    """
    n = origin_id
    path = [n]
    hops = 0
    while True:
        n_succ = ring.succ_list[n][0]
        if in_interval(key, n, n_succ, inc_right=True) or n == n_succ:
            return path
        nxt = ring.closest_preceding(n, key)
        if nxt == n:
            return path
        n = nxt
        path.append(n)
        hops += 1
        if hops > _SAFETY:
            return path


def misroute_walk(ring: ChordRing, origin_id: int, key: int,
                  mal_ids: set[int]) -> tuple[int, int]:
    """Port of node/chord.py::find_successor with the ``misroute`` override. Returns (owner_id, hops).

    A misrouter's ``closest_preceding`` returns itself, so when the walk reaches one (and the key is
    not already in its own successor interval — ``get_successor`` is NOT overridden) the ``nxt == n``
    early-exit fires and the walk returns that node's real successor = the WRONG owner. ``origin_id``
    is node 0, always honest.
    """
    n = origin_id
    hops = 0
    while True:
        n_succ = ring.succ_list[n][0]
        if in_interval(key, n, n_succ, inc_right=True) or n == n_succ:
            return n_succ, hops
        if n in mal_ids:
            # misrouter: closest_preceding(n,key) -> n -> nxt == n -> early exit at the wrong owner.
            return n_succ, hops
        nxt = ring.closest_preceding(n, key)
        if nxt == n:
            return n_succ, hops
        n = nxt
        hops += 1
        if hops > _SAFETY:
            return n_succ, hops


def true_owner(ring: ChordRing, key: int) -> int:
    """The honest owner of ``key`` (converged-ring ground truth)."""
    return ring.successor_of(key)


def dht_denied(ring: ChordRing, origin_id: int, key: int, mal_ids: set[int],
               s: int = DEFAULT_S) -> bool:
    """True iff the misrouted lookup actually DENIES the chunk's DHT read: it lands on the wrong
    primary and that primary's s-replica set shares NO node with the true replica set that holds the
    chunk. STRONGER than routing-eclipse (wrong owner): a wrong primary near the true owner shares
    successors, so the s-replica read still finds the chunk — replication rescues the gap (the routing
    mirror of B3's majority-vote rescue of censorship). Host-side analog of
    b4_inproc.real_dht_eclipse (store overlap), via converged-ring replica-set overlap."""
    owner, _ = misroute_walk(ring, origin_id, key, mal_ids)
    if owner == true_owner(ring, key):
        return False
    wrong_reps = set(_replica_set(ring, owner, s))
    true_reps = set(_replica_set(ring, true_owner(ring, key), s))
    return wrong_reps.isdisjoint(true_reps)


# --------------------------------------------------------------------------------------------
# Eclipse bound + realized fraction (a lookup is eclipsed iff misroute_walk lands on the wrong owner).
# --------------------------------------------------------------------------------------------
def eclipse_bound(f: float, mean_hops: float) -> float:
    """i.i.d. reference: a lookup crossing ``mean_hops`` independent nodes, each malicious w.p. f, is
    eclipsed unless none are — 1 − (1−f)^L̄. The realized structural fraction is the bound this run
    should actually match (finger-table centrality pushes it above this reference at low f)."""
    return 1.0 - (1.0 - f) ** mean_hops


def structural_eclipsed_fraction(mal_set: list[int], n: int, seed: int = DEFAULT_SEED,
                                 s: int = DEFAULT_S,
                                 domains: list[str] | None = None) -> float:
    """Realized bound: fraction of served chunks whose lookup from node 0 lands on the WRONG owner
    under this exact seeded placement + real fingered ring. Returns 0.0 for the empty (honest) set.
    """
    ring, idx2id, id2idx = build_routing_ring(n, s)
    origin = idx2id[0]
    mal_ids = {idx2id[i] for i in mal_set}
    if domains is None:
        domains = load_served_domains()
    if not domains or not mal_ids:
        return 0.0
    eclipsed = 0
    for d in domains:
        key = chunk_id(d)
        owner, _ = misroute_walk(ring, origin, key, mal_ids)
        if owner != true_owner(ring, key):
            eclipsed += 1
    return eclipsed / len(domains)


def honest_mean_hops(n: int, s: int = DEFAULT_S, domains: list[str] | None = None) -> float:
    """Mean honest routing hops from node 0 over the served chunks (L̄ for the i.i.d. reference)."""
    ring, idx2id, id2idx = build_routing_ring(n, s)
    origin = idx2id[0]
    if domains is None:
        domains = load_served_domains()
    if not domains:
        return 0.0
    return sum(len(honest_path(ring, origin, chunk_id(d))) - 1 for d in domains) / len(domains)


# --------------------------------------------------------------------------------------------
# Targeted eclipse: isolate a victim node's whole key range (or a single victim chunk).
# --------------------------------------------------------------------------------------------
def node_ownership(ring: ChordRing, id2idx: dict[int, int],
                   domains: list[str]) -> Counter:
    """Count how many served chunks each node index is the PRIMARY (owner) of."""
    owners: Counter = Counter()
    for d in domains:
        owners[id2idx[ring.successor_of(chunk_id(d))]] += 1
    return owners


def pick_victim(ring: ChordRing, id2idx: dict[int, int], domains: list[str]) -> int:
    """Auto victim = the non-anchor node (index != 0) owning the most served chunks."""
    owners = node_ownership(ring, id2idx, domains)
    for idx, _cnt in owners.most_common():
        if idx != 0:
            return idx
    raise ValueError("no non-anchor node owns any served chunk (unexpected)")


def victim_eclipse_indices(n: int, s: int, seed: int,
                           victim: int | None = None,
                           victim_chunk: str | None = None) -> tuple[list[int], dict]:
    """Minimal misrouter set that eclipses a victim's lookups from node 0.

    victim_chunk given  -> eclipse that ONE domain (corrupt the first on-path hop toward its key).
    victim given / auto -> eclipse the victim NODE's ENTIRE key range (the chunks it owns), by
                           corrupting the single most-common first on-path hop across those chunks.

    Returns (indices, meta) where meta carries the victim, its chunk count, and the realized eclipse
    rate over the targeted set. Excludes node 0, the victim itself, and the victim's immediate
    predecessor from the candidate hops (corrupting the predecessor is useless — get_successor is
    not overridden, so it still returns the true owner).
    """
    ring, idx2id, id2idx = build_routing_ring(n, s)
    origin = idx2id[0]
    domains = load_served_domains()

    if victim_chunk and victim_chunk != "auto":
        if victim_chunk not in set(domains):
            raise ValueError(f"victim-chunk {victim_chunk!r} is not in the served set")
        targets = [victim_chunk]
        victim_idx = id2idx[ring.successor_of(chunk_id(victim_chunk))]
        kind = "chunk"
    else:
        victim_idx = pick_victim(ring, id2idx, domains) if victim is None else victim
        victim_id = idx2id[victim_idx]
        targets = [d for d in domains if ring.successor_of(chunk_id(d)) == victim_id]
        kind = "node"
    if not targets:
        raise ValueError("victim owns no served chunk; pick another victim")

    victim_id = idx2id[victim_idx]
    pred_id = ring.ids[(ring.pos[victim_id] - 1) % ring.n]      # victim's immediate predecessor
    forbidden = {origin, victim_id, pred_id}

    # The first useful on-path hop toward each target; tally and take the most common single node.
    first_hops: Counter = Counter()
    for d in targets:
        for node in honest_path(ring, origin, chunk_id(d))[1:]:
            if node not in forbidden:
                first_hops[node] = first_hops[node] + 1
                break
    if not first_hops:
        raise ValueError("no corruptible on-path hop toward the victim (unexpected)")
    attacker_id = first_hops.most_common(1)[0][0]
    mal = [id2idx[attacker_id]]

    mal_ids = {attacker_id}
    denied = sum(1 for d in targets if dht_denied(ring, origin, chunk_id(d), mal_ids, s))
    routing = sum(1 for d in targets
                  if misroute_walk(ring, origin, chunk_id(d), mal_ids)[0]
                  != true_owner(ring, chunk_id(d)))
    meta = {
        "kind": kind,
        "victim_idx": victim_idx,
        "victim_chunk": victim_chunk if kind == "chunk" else "",
        "victim_chunk_count": len(targets),
        "attacker_idx": id2idx[attacker_id],
        "target_eclipse_rate_pct": round(100.0 * denied / len(targets), 4),      # DHT denial = real harm
        "target_routing_eclipse_pct": round(100.0 * routing / len(targets), 4),
    }
    return sorted(mal), meta


def structural_denied_fraction(mal_set: list[int], n: int, seed: int = DEFAULT_SEED,
                               s: int = DEFAULT_S,
                               domains: list[str] | None = None) -> float:
    """Realized DHT-denial fraction: served chunks whose s-replica read finds NOTHING under this
    placement (the real harm; `structural_eclipsed_fraction` counts the looser wrong-owner event)."""
    ring, idx2id, id2idx = build_routing_ring(n, s)
    origin = idx2id[0]
    mal_ids = {idx2id[i] for i in mal_set}
    if domains is None:
        domains = load_served_domains()
    if not domains or not mal_ids:
        return 0.0
    return sum(1 for d in domains if dht_denied(ring, origin, chunk_id(d), mal_ids, s)) / len(domains)


# --------------------------------------------------------------------------------------------
# Self-test — the plan's verification step 1 (no Docker, deterministic).
# --------------------------------------------------------------------------------------------
def _self_test() -> int:
    n, s = DEFAULT_N, DEFAULT_S
    domains = load_served_domains()
    L = honest_mean_hops(n, s, domains)
    print(f"[self-test] N={n} s={s} served={len(domains)} honest-mean-hops L̄={L:.3f}")

    ok = True
    # (a) honest control f=0 -> exactly 0% eclipse; (b) routing-eclipse rises monotonically with f;
    #     DHT-denial (the real harm) is lower — replication rescues the gap.
    prev = -1.0
    for f_pct, n_mal in zip([0, 10, 20, 30, 40, 50], [0, 3, 6, 10, 13, 16]):
        f = n_mal / n
        idxs = [random_indices(n, n_mal, DEFAULT_SEED + r) for r in range(8)] if n_mal else [[]]
        rout = sum(structural_eclipsed_fraction(ix, n, DEFAULT_SEED, s, domains) for ix in idxs) / len(idxs)
        deny = sum(structural_denied_fraction(ix, n, DEFAULT_SEED, s, domains) for ix in idxs) / len(idxs)
        ref = eclipse_bound(f, L)
        mono = "ok" if rout >= prev - 1e-9 else "NON-MONO"
        if f_pct == 0 and (rout != 0.0 or deny != 0.0):
            ok = False
        if mono == "NON-MONO" or deny > rout + 1e-9:        # denial can never exceed routing-eclipse
            ok = False
        print(f"  f={f_pct:>2}% n_mal={n_mal:>2} realized f={f:.4f} "
              f"routing-ecl={rout:.4f} DHT-denied={deny:.4f} i.i.d.-ref={ref:.4f}  [{mono}]")
        prev = rout

    # (c) targeted victim-NODE eclipse: one misrouter DENIES the victim's whole key range (real harm).
    mal, meta = victim_eclipse_indices(n, s, DEFAULT_SEED)
    node0_free = 0 not in mal
    full = meta["target_eclipse_rate_pct"] >= 99.0
    print(f"  targeted(node) victim_idx={meta['victim_idx']} owns={meta['victim_chunk_count']} "
          f"attacker={mal} denied={meta['target_eclipse_rate_pct']:.1f}% "
          f"(routing-ecl {meta['target_routing_eclipse_pct']:.1f}%) node0_free={node0_free}")
    ok = ok and node0_free and full and len(mal) == 1

    # (d) targeted victim-CHUNK (most popular): one misrouter usually DOES NOT deny a single popular
    #     chunk — replication rescues it (routing-eclipsed but still served). Reported, not asserted.
    mal_c, meta_c = victim_eclipse_indices(n, s, DEFAULT_SEED, victim_chunk=domains[0])
    print(f"  targeted(chunk) victim_chunk={domains[0]!r} attacker={mal_c} "
          f"denied={meta_c['target_eclipse_rate_pct']:.1f}% "
          f"(routing-ecl {meta_c['target_routing_eclipse_pct']:.1f}%) "
          f"-> single-misrouter chunk denial is unreliable (replication rescue)")
    ok = ok and 0 not in mal_c

    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="B4 malicious-node (misroute) placement (issue #45).")
    ap.add_argument("--n", type=int, default=DEFAULT_N, help="ring size N (default 32)")
    ap.add_argument("--s", type=int, default=DEFAULT_S, help="replication factor (default 3)")
    ap.add_argument("--n-mal", type=int, default=0, help="number of malicious nodes (random)")
    ap.add_argument("--placement", choices=["random", "targeted"], default="random")
    ap.add_argument("--victim", type=int, default=None,
                    help="targeted: victim node index to eclipse (default = max-ownership node)")
    ap.add_argument("--victim-chunk", default=None,
                    help="targeted: eclipse ONE domain instead of a whole node's range")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--out", type=Path, default=None,
                    help="also write JSON metadata (f_pct, n_mal, placement, indices, victim) here")
    ap.add_argument("--self-test", action="store_true", help="run the deterministic self-test")
    a = ap.parse_args()

    if a.self_test:
        return _self_test()

    victim_meta: dict = {}
    if a.placement == "random":
        indices = random_indices(a.n, a.n_mal, a.seed)
    else:
        indices, victim_meta = victim_eclipse_indices(a.n, a.s, a.seed, a.victim, a.victim_chunk)

    n_mal = len(indices)
    meta = {
        "n": a.n, "s": a.s, "placement": a.placement, "seed": a.seed, "mode": "misroute",
        "n_mal": n_mal, "f_pct": round(100.0 * n_mal / a.n, 4),
        "indices": ",".join(str(i) for i in indices),
        **victim_meta,
    }
    if a.out is not None:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(meta, indent=2) + "\n")
    # stdout = just the index list, for shell capture (empty line when n_mal==0 → all honest).
    print(meta["indices"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
