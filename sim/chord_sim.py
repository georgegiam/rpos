"""Phase 5 (#25, P5-1) — SimPy Chord ring model.

The foundation module of the Phase 5 simulator. It models N nodes on a Chord ring in their
**converged state**: finger tables and successor lists are computed *analytically* (a pure
function of the node-id set), so there is no stabilize/join protocol to simulate. On top of that
topology it reproduces ``node/chord.py``'s **iterative** ``find_successor`` exactly, so the hop
counts this simulator reports match the emulation testbed's routing.

Two concerns are kept deliberately separate:

* **Routing** (``ChordRing.route``) — deterministic, no SimPy, no per-call randomness. A pure
  function of (node ids, key). Later sub-issues (#29 calibration, #26 query path) can call it
  millions of times without spinning up a SimPy environment, and it is what proves the
  "O(log N) hops" acceptance criterion.
* **Timing** (``lookup_latency``) — a SimPy generator process that replays a routed path in
  simulated time, charging a per-hop processing + network delay. #26 layers parallel replica
  fan-out / majority vote / fallback on top of this as concurrent SimPy sub-processes.

Reuse: identifier maths (``in_interval``, ``node_id_from_pk``, ``RING_SIZE``) is imported from
``node/ids.py`` rather than reimplemented — a subtle wrap/``a==b`` divergence there would
silently change hop counts and break calibration (#29). ``node/chord.py`` itself is *not*
imported (it is bound to the asyncio message bus); its routing logic is mirrored here.

Run the self-test:  ``python -m sim.chord_sim``  (or ``python sim/chord_sim.py``).

Calibration note (stated openly, per CLAUDE.md "flag, don't hide"): pure-Chord routing here
matches **theory ≈ ½·log₂N** (N=8 → 1.5, N=32 → 2.5). It does NOT match the emulation *median*
hop count (2, 3 in results/PARAMETERS.md §2). That +0.5 offset — and the further +3 seen in the
raw ``hops`` column — come from replica reads and the fallback DNS-hierarchy referral chain,
which are modelled in #26, not here. chord_sim must therefore **not** be tuned to hit 2/3, or
those offsets would be double-counted once #26 lands.
"""
from __future__ import annotations

import bisect
import math
import os
import random
import statistics
import sys
from dataclasses import dataclass

# --- make the sibling ``node`` package importable for both `python -m sim.chord_sim`
#     and `python sim/chord_sim.py` (no packaging/setup.py in this repo). -------------
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from node.ids import RING_SIZE, in_interval, node_id_from_pk  # noqa: E402  (after sys.path)

# Ring constants mirrored from node/chord.py so routing is byte-identical in behaviour.
M = 160                 # finger-table entries (== RING_BITS)
SUCC_LIST_LEN = 3       # successor-list length (chord.py SUCC_LIST_LEN)
_SAFETY_HOPS = M + SUCC_LIST_LEN + 4   # chord.py's transient-loop safety valve

# Frozen defaults from results/PARAMETERS.md (Phase 4).
DEFAULT_SEED = 20260919
DEFAULT_REGIONS = 2
DEFAULT_PROC_DELAY_MS = 1.0    # calibratable placeholder — per-hop CPU time is unmeasured (#29)
DEFAULT_INTRA_MS = 5.0         # one-way, same region
DEFAULT_INTER_MS = 50.0        # one-way, cross region


@dataclass
class RouteResult:
    """Outcome of an analytical Chord lookup.

    responsible : node id that owns ``key`` (== successor_of(key) in a converged ring).
    hops        : forwarding-step count, matching node/chord.py's ``find_successor``.
    path        : ordered node ids visited [origin, n1, ..., holder]; ``hops == len(path) - 1``.
                  The timing layer (and #26) need this ordered sequence to charge per-hop delay.
    """
    responsible: int
    hops: int
    path: list[int]


class ChordRing:
    """A converged Chord ring of ``n`` nodes with analytically-built routing state."""

    def __init__(
        self,
        n: int,
        *,
        seed: int = DEFAULT_SEED,
        regions: int = DEFAULT_REGIONS,
        proc_delay_ms: float = DEFAULT_PROC_DELAY_MS,
        intra_ms: float = DEFAULT_INTRA_MS,
        inter_ms: float = DEFAULT_INTER_MS,
        ids: list[int] | None = None,
        build_fingers: bool = True,
    ) -> None:
        # ``ids`` (optional): use this explicit node-id set instead of generating one from
        #   (n, seed). ``sim/churn_sim.py`` (#28) uses it to rebuild a converged ring over the
        #   *currently-live* subset after each join/leave, reusing this class's placement /
        #   successor-list logic verbatim rather than duplicating it. When given, ``n`` is
        #   ignored and taken from the id set.
        # ``build_fingers`` (optional): skip the O(N·M) finger-table build when a caller needs
        #   only owner / successor-list placement (churn availability), not multi-hop routing.
        #   ``route``/``closest_preceding`` stay correct with empty fingers (they fall back to the
        #   successor list); the default True preserves the #25/#26/#27 behaviour exactly.
        if ids is not None:
            uniq = sorted(set(ids))
            if not uniq:
                raise ValueError("ids must be non-empty")
            self.ids = uniq
            self.n = len(uniq)
        else:
            if n < 1:
                raise ValueError("n must be >= 1")
            self.n = n
            self.ids = self._generate_ids(n, seed)      # sorted ascending
        self.seed = seed
        self.regions = max(1, regions)
        self.proc_delay_ms = proc_delay_ms
        self.intra_ms = intra_ms
        self.inter_ms = inter_ms

        self.pos = {nid: i for i, nid in enumerate(self.ids)}
        # Region assigned by sorted index, deterministic (PARAMETERS.md §1).
        self.region = {nid: i % self.regions for i, nid in enumerate(self.ids)}

        # Converged routing state, computed analytically (no stabilize protocol).
        self.succ_list: dict[int, list[int]] = {nid: self._compute_succ_list(nid) for nid in self.ids}
        self.fingers: dict[int, list[int]] = (
            {nid: self._compute_fingers(nid) for nid in self.ids} if build_fingers else {}
        )

    # ---------- construction helpers ----------
    @staticmethod
    def _generate_ids(n: int, seed: int) -> list[int]:
        """n distinct node ids drawn from the SAME SHA-256(pk) distribution the emulation uses.

        Hashed (not evenly spaced) ids give realistic non-uniform ring gaps, which matters for
        the hop-count tail and for #29 matching. Seeded → identical ring every run.
        """
        rng = random.Random(seed)
        ids: set[int] = set()
        while len(ids) < n:
            ids.add(node_id_from_pk(rng.randbytes(32)))   # collisions at 160 bits are astronomically rare
        return sorted(ids)

    def _compute_succ_list(self, nid: int) -> list[int]:
        """The next SUCC_LIST_LEN distinct nodes clockwise from ``nid`` (chord.py successor_list)."""
        i = self.pos[nid]
        out: list[int] = []
        k = 1
        while len(out) < SUCC_LIST_LEN and k <= self.n:
            cand = self.ids[(i + k) % self.n]
            if cand != nid and cand not in out:
                out.append(cand)
            k += 1
        return out or [nid]      # degenerate n==1: a node alone is its own successor

    def _compute_fingers(self, nid: int) -> list[int]:
        """finger[i] = successor_of((nid + 2**i) mod 2**160), i in 0..M-1 (converged state)."""
        return [self.successor_of((nid + (1 << i)) % RING_SIZE) for i in range(M)]

    # ---------- analytical routing (no SimPy, no randomness) ----------
    def successor_of(self, key: int) -> int:
        """First node id clockwise at or after ``key`` on the ring."""
        idx = bisect.bisect_left(self.ids, key % RING_SIZE)
        return self.ids[idx % self.n]

    def closest_preceding(self, node_id: int, key: int) -> int:
        """Highest node in node_id's tables strictly preceding ``key`` (port of chord.py)."""
        for f in reversed(self.fingers.get(node_id, ())):   # empty when build_fingers=False
            if f != node_id and in_interval(f, node_id, key):
                return f
        for s in reversed(self.succ_list[node_id]):
            if s != node_id and in_interval(s, node_id, key):
                return s
        return node_id

    def route(self, origin_id: int, key: int) -> RouteResult:
        """Iterative Chord lookup from ``origin_id`` for ``key`` (exact port of chord.py)."""
        n = origin_id
        hops = 0
        path = [origin_id]
        while True:
            n_succ = self.succ_list[n][0]      # successor of n
            if in_interval(key, n, n_succ, inc_right=True) or n == n_succ:
                return RouteResult(n_succ, hops, path)
            nxt = self.closest_preceding(n, key)
            if nxt == n:
                return RouteResult(n_succ, hops, path)
            n = nxt
            hops += 1
            path.append(n)
            if hops > _SAFETY_HOPS:            # transient-loop guard (matches chord.py)
                return RouteResult(n_succ, hops, path)

    def route_hops(self, origin_id: int, key: int) -> int:
        """Convenience: just the hop count (no env needed)."""
        return self.route(origin_id, key).hops

    # ---------- timing primitive ----------
    def hop_delay_ms(self, a_id: int, b_id: int) -> float:
        """One-way per-hop delay: processing + network (network by region pair)."""
        net = self.intra_ms if self.region[a_id] == self.region[b_id] else self.inter_ms
        return self.proc_delay_ms + net


def lookup_latency(env, ring: ChordRing, origin_id: int, key: int):
    """SimPy process: replay ``ring.route`` in simulated time.

    Yields one ``env.timeout`` per hop and returns ``(RouteResult, latency_ms)``. Charges the
    delay **one-way** per hop by default (matches the frozen 5/50 ms figures); whether a hop
    should cost one-way or a full RTT is the main latency-calibration lever for #29 and is
    controlled by the ring's delay parameters.
    """
    rr = ring.route(origin_id, key)
    latency = 0.0
    prev = origin_id
    for nxt in rr.path[1:]:
        d = ring.hop_delay_ms(prev, nxt)
        yield env.timeout(d)
        latency += d
        prev = nxt
    return rr, latency


# ---------------------------------------------------------------------------
# Self-test / demo — satisfies issue #25 "done when": a lookup at N=1000
# completes with the expected hop count (≈ ½·log₂N).
# ---------------------------------------------------------------------------
def _hop_stats(n: int, trials: int = 2000, seed: int = DEFAULT_SEED):
    ring = ChordRing(n, seed=seed)
    rng = random.Random(seed ^ n)
    hops: list[int] = []
    owner_ok = 0
    for _ in range(trials):
        origin = rng.choice(ring.ids)
        key = rng.randrange(RING_SIZE)
        rr = ring.route(origin, key)
        hops.append(rr.hops)
        if rr.responsible == ring.successor_of(key):
            owner_ok += 1
    return {
        "median": statistics.median(hops),
        "mean": statistics.fmean(hops),
        "max": max(hops),
        "owner_pct": 100.0 * owner_ok / trials,
        "ring": ring,
    }


def _run_self_test() -> int:
    sizes = [8, 32, 100, 1000]
    trials = 2000
    print(f"Chord ring simulator — hop counts over {trials} random lookups (seed {DEFAULT_SEED})")
    print(f"{'N':>6} {'theory ½log2N':>14} {'median':>7} {'mean':>7} {'max':>5} {'owner-correct':>14}")
    stats_by_n = {}
    for n in sizes:
        s = _hop_stats(n, trials=trials)
        stats_by_n[n] = s
        theory = 0.5 * math.log2(n)
        print(f"{n:>6} {theory:>14.2f} {s['median']:>7.1f} {s['mean']:>7.2f} "
              f"{s['max']:>5} {s['owner_pct']:>13.1f}%")

    ok = True
    # (1) Owner-correctness across every size: routing lands on the true owner.
    for n, s in stats_by_n.items():
        if s["owner_pct"] != 100.0:
            print(f"FAIL: N={n} owner-correctness {s['owner_pct']:.2f}% (expected 100%)")
            ok = False

    # (2) Acceptance criterion at N=1000: mean hops ≈ ½·log₂N, O(log N) bound holds.
    n = 1000
    s = stats_by_n[n]
    expected = 0.5 * math.log2(n)                 # ≈ 4.98
    rel_err = abs(s["mean"] - expected) / expected
    if rel_err >= 0.20:
        print(f"FAIL: N=1000 mean hops {s['mean']:.2f} vs theory {expected:.2f} (rel err {rel_err:.0%})")
        ok = False
    bound = math.log2(n) + SUCC_LIST_LEN          # generous O(log N) ceiling
    if s["max"] > bound:
        print(f"FAIL: N=1000 max hops {s['max']} exceeds O(log N) bound {bound:.1f}")
        ok = False

    # (2b) Explicit-ids construction (used by churn_sim #28) is equivalent to generated-ids.
    #      * A ring built from an existing ring's id set routes IDENTICALLY (full fingers).
    #      * build_fingers=False (the churn availability path) preserves owner/successor-list
    #        PLACEMENT — churn_sim resolves owners via successor_of, not multi-hop route, so that
    #        is the invariant it relies on (multi-hop route needs fingers and is not used there).
    base = stats_by_n[1000]["ring"]
    same = ChordRing(0, ids=base.ids, seed=DEFAULT_SEED)             # n ignored when ids given
    lite = ChordRing(0, ids=base.ids, seed=DEFAULT_SEED, build_fingers=False)
    if not (same.ids == base.ids == lite.ids and same.succ_list == base.succ_list == lite.succ_list):
        print("FAIL: explicit-ids ring has different ids/successor-list placement")
        ok = False
    rng = random.Random(DEFAULT_SEED ^ 0xC0FFEE)
    for _ in range(500):
        origin = rng.choice(base.ids)
        key = rng.randrange(RING_SIZE)
        rr_base = base.route(origin, key)
        if same.route(origin, key) != rr_base:
            print("FAIL: explicit-ids ring does not route identically to generated-ids ring")
            ok = False
            break
        if lite.successor_of(key) != rr_base.responsible:
            print("FAIL: build_fingers=False changed the resolved owner (successor_of)")
            ok = False
            break

    # (3) SimPy timing smoke test (skipped cleanly if simpy is not installed).
    try:
        import simpy
    except ImportError:
        print("NOTE: simpy not installed — timing smoke test skipped "
              "(`pip install simpy` to enable). Hop-count acceptance is unaffected.")
    else:
        ring = stats_by_n[1000]["ring"]
        rng = random.Random(DEFAULT_SEED)
        origin, key = rng.choice(ring.ids), rng.randrange(RING_SIZE)
        env = simpy.Environment()
        holder = {}

        def _drive():
            holder["res"] = yield from lookup_latency(env, ring, origin, key)

        env.process(_drive())
        env.run()
        rr, latency = holder["res"]
        expected_lat = sum(
            ring.hop_delay_ms(rr.path[i], rr.path[i + 1]) for i in range(len(rr.path) - 1)
        )
        assert env.now > 0 and abs(latency - expected_lat) < 1e-6 and abs(env.now - latency) < 1e-6
        print(f"SimPy timing OK: N=1000 lookup — {rr.hops} hops, latency {latency:.1f} ms "
              f"(sim clock {env.now:.1f} ms).")

    print()
    print("Note: these are pure-Chord routing hops and match THEORY (½·log₂N), not the emulation")
    print("median (2 at N=8, 3 at N=32). The +0.5 and +3 offsets come from replica reads and the")
    print("fallback DNS hierarchy, which are modelled in #26 — chord_sim is not tuned to them.")
    print("PASS" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(_run_self_test())
