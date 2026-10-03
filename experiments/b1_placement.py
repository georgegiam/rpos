#!/usr/bin/env python3
"""Issue #42 [B1] — malicious-node placement helper for the tampering / cache-poisoning run.

B1 makes a fraction ``f`` of the N=32 ring run in ``lie`` mode (node/malicious.py returns the
forged A-record ``6.6.6.6``) and measures how often clients accept the forgery, against the
majority-vote bound (a chunk is captured only when >= ceil((s+1)/2) of its s replicas lie).

This module is the DRIVER's placement brain (CLAUDE.md §2 — new code in a new file; it imports
read-only and touches no protocol / frozen artifact). It runs on the HOST before bring-up, so
it must NOT import testbed/query_gen.py (that pulls in dnspython, absent on the host). It picks
WHICH node indices are malicious and prints them as a comma list for
``gen_nodes_compose.py --malicious-indices`` (via run_experiment.sh).

Two placement strategies:

  * random   — f*N nodes chosen uniformly from indices 1..N-1 (node 0, the seed/entry anchor,
               is never malicious — mirrors A6's injector). Over many chunks the captured
               fraction tracks the analytic bound ``3f^2 - 2f^3`` (s=3).
  * targeted — co-locate the minimum capturing budget (ceil((s+1)/2) = 2 at s=3) on ONE popular
               target chunk's replica set, so that chunk is forged regardless of the global f.
               This is the colluding case that CROSSES the bound. (B1 corrupts nodes that
               ALREADY own the target chunk to isolate the vote-crossing effect; the cost of
               achieving such placement by grinding ids is B2, not B1.)

Reproducibility (CLAUDE.md §2): node identities are the exact emulation ones —
``node_id_from_pk(_pk_for(i))`` — and replica sets come from ``sim/chord_sim.ChordRing`` +
``sim/query_sim._replica_set`` (the same converged ``owner + succ_list[:s]`` rule the node and
the other sims use), so everything is bit-for-bit reconstructible from (N, s, seed).

CLI (prints the malicious index list to stdout; optional JSON metadata to --out):

    python3 b1_placement.py --n 32 --s 3 --n-mal 6 --placement random --seed 20260919
    python3 b1_placement.py --placement targeted --budget 2 --seed 20260919 --out place.json
    python3 b1_placement.py --self-test
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from node.ids import chunk_id, node_id_from_pk          # noqa: E402 (hashlib-only, host-safe)
from sim.chord_sim import ChordRing                      # noqa: E402
from sim.query_sim import _replica_set                   # noqa: E402


def _pk_for(index: int) -> bytes:
    """Deterministic 33-byte public key for node ``index`` — IDENTICAL to node/run_node._pk_for
    and testbed/query_gen._pk_for. Replicated here (one trivial pure function) so the host-side
    placement does not import the whole node stack, which pulls in dnspython (absent on host)."""
    return b"node-pk-" + index.to_bytes(4, "big") + b"\x00" * 21

DEFAULT_SEED = 20260919     # frozen (results/PARAMETERS.md §1)
DEFAULT_N = 32              # emulation ceiling
DEFAULT_S = 3              # replication factor
DEFAULT_COUNT = 1000       # served Tranco domains

_MANIFEST = REPO_ROOT / "testbed" / "dns" / "zones" / "MANIFEST.json"
_TRANCO = REPO_ROOT / "testbed" / "dns" / "tranco" / "tranco_JZNVY_top100k.csv"


# --------------------------------------------------------------------------------------------
# Served domain set — EXACTLY what testbed/query_gen.py queries (rank-ordered), but loaded via
# the pure-stdlib generate_zones so the host needs no dnspython. Prefer MANIFEST.json (the real
# served set); otherwise reproduce it from the vendored Tranco list.
# --------------------------------------------------------------------------------------------
def load_served_domains(count: int = DEFAULT_COUNT) -> list[str]:
    sys.path.insert(0, str(REPO_ROOT / "testbed" / "dns"))
    import generate_zones as gz   # pure stdlib (argparse/csv/hashlib/json/random/sys/pathlib)

    if _MANIFEST.exists():
        with open(_MANIFEST) as f:
            domain_set = list(json.load(f)["records"].keys())
    elif _TRANCO.exists():
        ranked = gz.read_tranco(_TRANCO)
        domain_set, _ = gz.select_domains(ranked, ["com", "org"], count)
    else:
        raise SystemExit(f"no MANIFEST at {_MANIFEST} and no Tranco CSV at {_TRANCO}")

    # Rank by global Tranco popularity so index 0 is the genuinely most-popular domain
    # (identical ordering to query_gen.load_domains).
    if _TRANCO.exists():
        rank = {d: i for i, d in enumerate(gz.read_tranco(_TRANCO))}
        return sorted(domain_set, key=lambda d: rank.get(d, len(rank)))
    return domain_set


# --------------------------------------------------------------------------------------------
# Ring identities + replica sets (converged-ring model, shared with the simulator).
# --------------------------------------------------------------------------------------------
def index_to_id_map(n: int) -> dict[int, int]:
    """Node index i -> ring id node_id_from_pk(_pk_for(i)) (the exact emulation identity)."""
    return {i: node_id_from_pk(_pk_for(i)) for i in range(n)}


def build_ring(n: int, s: int = DEFAULT_S):
    """A converged ChordRing over the real emulation ids; returns (ring, id->index map)."""
    idx2id = index_to_id_map(n)
    ring = ChordRing(
        0, ids=list(idx2id.values()), seed=DEFAULT_SEED,
        build_fingers=False,                       # only placement is needed, not routing
        succ_list_len=max(3, s - 1),               # fill an s>4 replica set (mirrors A4)
    )
    id2idx = {v: k for k, v in idx2id.items()}
    return ring, id2idx


def replica_indices(domain: str, ring, id2idx: dict[int, int], s: int = DEFAULT_S) -> list[int]:
    """The s replica node INDICES responsible for ``domain``'s chunk (primary + successors)."""
    primary = ring.successor_of(chunk_id(domain))
    return [id2idx[nid] for nid in _replica_set(ring, primary, s)]


# --------------------------------------------------------------------------------------------
# The two placement strategies.
# --------------------------------------------------------------------------------------------
def capture_threshold(s: int = DEFAULT_S) -> int:
    """Replicas that must lie for a forged value to win the plurality vote: floor(s/2)+1."""
    return s // 2 + 1


def random_indices(n: int, n_mal: int, seed: int) -> list[int]:
    """n_mal distinct malicious indices chosen uniformly from 1..n-1 (node 0 stays honest)."""
    pool = list(range(1, n))
    if n_mal > len(pool):
        raise ValueError(f"n_mal={n_mal} exceeds available non-anchor nodes {len(pool)}")
    return sorted(random.Random(seed).sample(pool, n_mal))


def targeted_indices(n: int, s: int, budget: int, seed: int,
                     target: str | None = None) -> tuple[list[int], str]:
    """Co-locate the capturing budget on one popular target chunk's replica set.

    Returns (indices, target_domain). Picks (when target is None/"auto") the most popular served
    domain whose replica set excludes node 0, so only non-anchor nodes are corrupted. Uses the
    first ``capture_threshold(s)`` replicas; any remaining budget is spent on random other
    non-anchor, non-replica nodes.
    """
    ring, id2idx = build_ring(n, s)
    thresh = capture_threshold(s)
    if budget < thresh:
        raise ValueError(f"budget={budget} < capture threshold {thresh}; cannot capture a chunk")

    domains = load_served_domains()
    chosen_target = None
    reps: list[int] = []
    if target and target != "auto":
        reps = replica_indices(target, ring, id2idx, s)
        if 0 in reps:
            raise ValueError(f"target {target!r} has node 0 in its replica set {reps}; pick another")
        chosen_target = target
    else:
        for d in domains:                               # popularity order
            r = replica_indices(d, ring, id2idx, s)
            if 0 not in r and len(set(r)) >= thresh:
                reps, chosen_target = r, d
                break
        if chosen_target is None:
            raise ValueError("no served domain has a node-0-free replica set (unexpected)")

    mal = list(dict.fromkeys(reps))[:thresh]            # the co-located capturing set
    if budget > thresh:                                 # spend the rest at random, node 0 excluded
        extra_pool = [i for i in range(1, n) if i not in mal]
        mal += random.Random(seed).sample(extra_pool, min(budget - thresh, len(extra_pool)))
    return sorted(mal), chosen_target


# --------------------------------------------------------------------------------------------
# Bounds (for the analyzer's overlay).
# --------------------------------------------------------------------------------------------
def analytic_bound(f: float, s: int = DEFAULT_S, thresh: int | None = None) -> float:
    """P(a random chunk has >= thresh malicious replicas) under i.i.d. random placement =
    P(Binom(s, f) >= thresh).

    thresh defaults to the MAJORITY threshold capture_threshold(s) — the INTENDED majority-vote
    bound (for s=3 the familiar 3 f^2 - 2 f^3). Pass thresh=1 for the EFFECTIVE/ACHIEVED bound
    1 - (1-f)^s: the implementation's vote skips abstaining (None) honest replicas and the liar
    fabricates unstored records, so a SINGLE malicious replica suffices (see B1_NOTES.md).
    """
    if thresh is None:
        thresh = capture_threshold(s)
    return sum(math.comb(s, k) * f**k * (1 - f) ** (s - k) for k in range(thresh, s + 1))


def effective_bound(f: float, s: int = DEFAULT_S) -> float:
    """The ACHIEVED bound the implementation actually exhibits: >= 1 malicious replica suffices."""
    return analytic_bound(f, s, thresh=1)


def structural_capture_fraction(mal_set: list[int], n: int, s: int,
                                domains: list[str] | None = None,
                                thresh: int | None = None) -> float:
    """Realized bound: fraction of the served chunks whose replica set has >= thresh malicious.

    Computed over the ACTUAL seeded placement + real ring, so it is the bound this specific run
    should match (the analytic form is the i.i.d. limit). thresh defaults to the majority
    threshold; pass thresh=1 for the effective (>=1 malicious) realized bound.
    """
    ring, id2idx = build_ring(n, s)
    if domains is None:
        domains = load_served_domains()
    mal = set(mal_set)
    if thresh is None:
        thresh = capture_threshold(s)
    if not domains:
        return 0.0
    captured = sum(
        1 for d in domains
        if len(set(replica_indices(d, ring, id2idx, s)) & mal) >= thresh
    )
    return captured / len(domains)


# --------------------------------------------------------------------------------------------
# Self-test — the plan's verification step 2 (no Docker, deterministic).
# --------------------------------------------------------------------------------------------
def _self_test() -> int:
    n, s = DEFAULT_N, DEFAULT_S
    domains = load_served_domains()
    print(f"[self-test] N={n} s={s} served={len(domains)} thresh={capture_threshold(s)}")

    # (a) random capture fraction tracks the analytic bound at each f.
    ok = True
    for f_pct, n_mal in zip([0, 10, 20, 30, 40, 50], [0, 3, 6, 10, 13, 16]):
        f = n_mal / n
        # average structural fraction over several independent placements ~ analytic bound
        vals = [structural_capture_fraction(random_indices(n, n_mal, DEFAULT_SEED + r), n, s, domains)
                for r in range(8)]
        measured = sum(vals) / len(vals)
        bound = analytic_bound(f, s)
        eff = effective_bound(f, s)
        tol = 0.05 + 0.15 * bound           # generous: finite ring + finite domain sample
        flag = "ok" if abs(measured - bound) <= tol else "OFF"
        if flag == "OFF":
            ok = False
        print(f"  f={f_pct:>2}% n_mal={n_mal:>2} realized f={f:.4f} "
              f"structural={measured:.4f} majority-bound={bound:.4f} effective-bound(≥1)={eff:.4f}  [{flag}]")

    # (b) targeted placement always captures its target with the minimum budget, node 0 free.
    mal, target = targeted_indices(n, s, capture_threshold(s), DEFAULT_SEED)
    ring, id2idx = build_ring(n, s)
    reps = replica_indices(target, ring, id2idx, s)
    captured = len(set(reps) & set(mal)) >= capture_threshold(s)
    node0_free = 0 not in mal
    print(f"  targeted target={target!r} replicas={reps} malicious={mal} "
          f"captured={captured} node0_free={node0_free}")
    ok = ok and captured and node0_free

    # (c) targeted target-chunk forged while global stays near the budget's random level.
    frac = structural_capture_fraction(mal, n, s, domains)
    print(f"  targeted global structural capture={frac:.4f} (one chunk forced, rest ~random)")

    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="B1 malicious-node placement (issue #42).")
    ap.add_argument("--n", type=int, default=DEFAULT_N, help="ring size N (default 32)")
    ap.add_argument("--s", type=int, default=DEFAULT_S, help="replication factor (default 3)")
    ap.add_argument("--n-mal", type=int, default=0, help="number of malicious nodes (random)")
    ap.add_argument("--placement", choices=["random", "targeted"], default="random")
    ap.add_argument("--budget", type=int, default=None,
                    help="targeted: malicious budget (default = capture threshold)")
    ap.add_argument("--target", default="auto",
                    help="targeted: domain to capture, or 'auto' (most popular node-0-free chunk)")
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
        budget = a.budget if a.budget is not None else capture_threshold(a.s)
        indices, target = targeted_indices(a.n, a.s, budget, a.seed, a.target)

    n_mal = len(indices)
    meta = {
        "n": a.n, "s": a.s, "placement": a.placement, "seed": a.seed,
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
