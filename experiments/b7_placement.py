#!/usr/bin/env python3
"""Issue #48 [B7] — placement brain for the DoS experiment (Phase 7, examiner point (ii)).

B7 has TWO attack blocks, so this helper answers two placement questions. It is the host-side
"brain" (CLAUDE.md §2 — new file, imports read-only, touches no frozen artifact) and it reuses
experiments/b1_placement.py VERBATIM for the shared ring/replica/identity model, so B7 is
provably consistent with B1/B3/B4 and bit-for-bit reconstructible from (N, s, seed).

  * blackhole block  — a fraction f of the ring runs MALICIOUS_MODE=drop (node/malicious.py's
                       _should_drop black-holes every inbound RPC). This is IDENTICAL placement to
                       B3 (reuses b1_placement.random_indices: f*N nodes from 1..N-1, node 0 the
                       honest seed/entry anchor). B7 reframes the metric onto the SYSTEMIC honest
                       query stream (all Zipf queries), not one censored chunk as in B3.
  * flood block      — a host-side flooder (experiments/b7_flooder.py) injects high-rate RPC
                       traffic at honest victim nodes. There is no "flood" node mode (all five
                       node modes are reactive inbound-handler overrides; a flood ORIGINATES
                       traffic), so B7 models the f attacker identities as host-side load with the
                       same wire effect and ZERO node-code change (flagged in B7_NOTES.md). This
                       function only chooses WHICH honest nodes the flooder targets:
                         - broad    (default) — every non-anchor node 1..N-1 (ring-wide flood);
                         - targeted           — one victim node + its two ring neighbours
                                                (predecessor + successor), to maximally disrupt
                                                that victim's stabilize cycle (the chord.py
                                                fragility epicentre, CLAUDE.md Phase 3).

CLI (prints a comma index list to stdout for run_b7.sh; optional JSON metadata to --out):

    python3 b7_placement.py --role blackhole --n 32 --s 3 --n-mal 6 --seed 20260919
    python3 b7_placement.py --role flood --flood broad   --n 32 --seed 20260919
    python3 b7_placement.py --role flood --flood targeted --n 32 --seed 20260919 --out p.json
    python3 b7_placement.py --self-test
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Reuse B1's placement model verbatim (identities, converged ring, replica sets, random draw).
from experiments.b1_placement import (  # noqa: E402
    DEFAULT_N, DEFAULT_S, DEFAULT_SEED,
    build_ring, index_to_id_map, random_indices, replica_indices,
    load_served_domains,
)


# --------------------------------------------------------------------------------------------
# Flood-target selection.
# --------------------------------------------------------------------------------------------
def broad_targets(n: int) -> list[int]:
    """Every non-anchor node (1..N-1). The flooder spreads its load ring-wide; node 0 (the honest
    query entry) is never a target so the probe always has a working entry point."""
    return list(range(1, n))


def ring_neighbours(victim_idx: int, n: int, s: int = DEFAULT_S) -> list[int]:
    """The victim's on-ring predecessor + successor INDICES (by ring-id order). Flooding a node's
    immediate neighbours is what starves its stabilize/get_predecessor exchange (chord.py drops a
    successor on any RPC timeout — the fragility B7 probes)."""
    idx2id = index_to_id_map(n)
    order = sorted(range(n), key=lambda i: idx2id[i])   # indices in ring-id order
    pos = order.index(victim_idx)
    pred = order[(pos - 1) % n]
    succ = order[(pos + 1) % n]
    return [pred, succ]


def targeted_victim(n: int, s: int = DEFAULT_S) -> int:
    """Auto victim = the non-anchor node that owns the most popular served chunk (so a focused
    flood on it denies a genuinely hot part of the keyspace). Deterministic from (N, s, seed)."""
    ring, id2idx = build_ring(n, s)
    for d in load_served_domains():                      # popularity order
        reps = replica_indices(d, ring, id2idx, s)
        if reps and reps[0] != 0:                        # primary is a non-anchor node
            return reps[0]
    raise ValueError("no served domain has a non-anchor primary (unexpected)")


def targeted_flood(n: int, s: int = DEFAULT_S) -> tuple[list[int], int]:
    """Victim node + its two ring neighbours = the focused-fire target set. Node 0 excluded.
    Returns (target_indices, victim_idx)."""
    victim = targeted_victim(n, s)
    targets = [victim] + ring_neighbours(victim, n, s)
    targets = sorted({i for i in targets if i != 0})     # never flood the honest entry anchor
    return targets, victim


# --------------------------------------------------------------------------------------------
# Self-test — deterministic, no Docker (plan verification step 1).
# --------------------------------------------------------------------------------------------
def _self_test() -> int:
    n, s = DEFAULT_N, DEFAULT_S
    ok = True

    # (a) blackhole random placement reuses B1's draw: n_mal distinct, node-0-free, in range.
    for f_pct, n_mal in zip([0, 10, 20, 30, 40, 50], [0, 3, 6, 10, 13, 16]):
        idx = random_indices(n, n_mal, DEFAULT_SEED) if n_mal else []
        good = (len(idx) == n_mal and len(set(idx)) == n_mal
                and all(1 <= i < n for i in idx) and 0 not in idx)
        ok = ok and good
        print(f"  blackhole f={f_pct:>2}% n_mal={n_mal:>2} indices={idx} "
              f"[{'ok' if good else 'OFF'}]")

    # (b) broad flood = all non-anchor nodes.
    broad = broad_targets(n)
    good_broad = (broad == list(range(1, n)) and 0 not in broad)
    ok = ok and good_broad
    print(f"  flood broad targets={len(broad)} (1..{n - 1}) node0_free={0 not in broad} "
          f"[{'ok' if good_broad else 'OFF'}]")

    # (c) targeted flood = victim + 2 neighbours, node-0-free, deterministic.
    targets, victim = targeted_flood(n, s)
    t2, v2 = targeted_flood(n, s)
    good_tgt = (0 not in targets and victim in targets and 1 <= len(targets) <= 3
                and targets == t2 and victim == v2)
    ok = ok and good_tgt
    print(f"  flood targeted victim=idx{victim} targets={targets} node0_free={0 not in targets} "
          f"deterministic={targets == t2} [{'ok' if good_tgt else 'OFF'}]")

    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="B7 DoS placement brain (issue #48).")
    ap.add_argument("--role", choices=["blackhole", "flood"], default="flood")
    ap.add_argument("--n", type=int, default=DEFAULT_N)
    ap.add_argument("--s", type=int, default=DEFAULT_S)
    ap.add_argument("--n-mal", type=int, default=0, help="blackhole: number of drop nodes")
    ap.add_argument("--flood", choices=["broad", "targeted"], default="broad",
                    help="flood: target selection")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--out", type=Path, default=None, help="also write JSON metadata here")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()

    if a.self_test:
        return _self_test()

    target = None
    if a.role == "blackhole":
        indices = random_indices(a.n, a.n_mal, a.seed) if a.n_mal else []
    elif a.flood == "broad":
        indices = broad_targets(a.n)
    else:
        indices, target = targeted_flood(a.n, a.s)

    meta = {
        "role": a.role, "n": a.n, "s": a.s, "seed": a.seed,
        "flood": a.flood if a.role == "flood" else None,
        "n_mal": len(indices), "f_pct": round(100.0 * len(indices) / a.n, 4),
        "indices": ",".join(str(i) for i in indices), "victim": target,
    }
    if a.out is not None:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(meta, indent=2) + "\n")
    print(meta["indices"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
