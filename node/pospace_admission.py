"""Sub-issue #14 — PoSpace admission (v3 DRG).

Sybil resistance: ring membership must be backed by a real Proof-of-Space plot. Each node
plots the frozen v3 DRG scheme (Phase 1, Fix A) keyed by its own public key, Merkle-commits
the labels, and publishes the commitment (root + pk). Peers challenge one another with a
random leaf index; the challenged node must return a valid opening (leaf + all its DRG
parents, each with a Merkle path) within the response timeout delta. A node that fails
`MAX_FAILS` challenges in a row is evicted.

Two design points (agreed for Phase 2):
  * Peer-to-peer — there is no central admission registry. Any node can challenge any peer,
    and the challenger drives eviction.
  * Join is gated — a joining node must pass one challenge from its successor before it is
    accepted into the ring.

The v3 scheme is IMPORTED from phase1/pospace_drg.py, never copied (repo ground rule). phase1
is not a package and its modules use bare sibling imports, so the phase1 directory is put on
sys.path at runtime, computed from __file__.

Periodic challenging is a driver-called coroutine (`challenge_round`), mirroring how
stabilize/fix_fingers are driven in rounds — this keeps runs deterministic under a fixed seed.

In-process transport only (Phase 3 swaps in sockets).
"""
import os
import random
import sys
import time

from node.ids import node_id_from_pk
from node.ledger import LedgerMixin
from node.logs import append_row, now_iso
from node.net import Network

# --- import the v3 DRG scheme from phase1/ (never copy it) ---
_PHASE1 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "phase1")
if _PHASE1 not in sys.path:
    sys.path.insert(0, _PHASE1)
from pospace_drg import plot_v3, commit_v3, prove_v3, verify_v3   # noqa: E402

POSPACE_CSV = "admission.csv"
POSPACE_HEADER = ["timestamp", "event", "node", "peer", "index", "result", "elapsed_s", "fails"]

CHALLENGE_TIMEOUT = 2.0        # response timeout delta (seconds) — acceptance criterion
MAX_FAILS = 3                  # consecutive failures before eviction — acceptance criterion
PLOT_N = 1 << 10              # test plot size (leaf count); must be a power of two
DRG_INDEGREE = 2              # DRG in-degree (phase1 sweeps {2, 4, 8}); 2 is the cheapest
DEFAULT_SEED = 20260919      # fixed => reproducible challenge indices (repo ground rule)

# Real thesis plot scale (NOT used at test scale; here for reference/config only):
# ~3.36e9 leaves ~= 200 GiB of 32-byte labels. See CLAUDE.md section 5.
REAL_PLOT_N = 3_355_443_200


class AdmissionError(Exception):
    """Raised when a joining node fails its admission challenge."""


class PoSpaceMixin(LedgerMixin):
    def __init__(self, pk: bytes, net: Network, plot_n: int = PLOT_N,
                 drg_indegree: int = DRG_INDEGREE, challenge_timeout: float = CHALLENGE_TIMEOUT,
                 seed: int = DEFAULT_SEED, **kwargs):
        super().__init__(pk, net, **kwargs)
        self.plot_n = plot_n
        self.drg_indegree = drg_indegree
        self.challenge_timeout = challenge_timeout
        # per-node RNG for challenge indices; mixing node_id keeps peers from lock-stepping
        self._rng = random.Random(seed ^ (self.node_id & ((1 << 64) - 1)))
        self.fail_counts: dict[int, int] = {}       # peer_id -> consecutive failures
        self.plot_levels: list | None = None        # Merkle levels (level 0 = labels)
        self.plot_root: bytes | None = None         # commitment root
        self.register("pospace_commitment", self._h_commitment)
        self.register("pospace_challenge", self._h_challenge)
        self.register("admit_peer", self._h_admit_peer)

    # ---------- plot + commitment ----------
    def _build_plot(self) -> None:
        """Plot the v3 DRG and Merkle-commit it. Cheap at test scale (~ms for N=1024)."""
        labels = plot_v3(self.pk, self.plot_n, self.drg_indegree)
        self.plot_levels, self.plot_root = commit_v3(labels)

    # ---------- RPC handlers (prover side) ----------
    async def _h_commitment(self, src):
        """Publish this node's commitment so a challenger can verify openings."""
        return (self.pk, self.plot_root, self.plot_n, self.drg_indegree)

    async def _h_challenge(self, src, i: int):
        """Open leaf i and all its DRG parents, each with a Merkle path."""
        return prove_v3(self.plot_levels, self.pk, self.plot_n, self.drg_indegree, i)

    async def _h_admit_peer(self, src):
        """Admitter side of the join gate: challenge the caller and report the verdict."""
        return await self.challenge_peer(src)

    # ---------- challenger side ----------
    async def challenge_peer(self, peer_id: int) -> bool:
        """Issue one v3 challenge to `peer_id` and verify the opening within the timeout.

        Updates the peer's consecutive-failure count, logs the outcome, and evicts the peer
        once it reaches MAX_FAILS. A timeout, transport error, wrong commitment binding, or a
        failed proof all count as one failure.
        """
        i = -1
        t0 = time.monotonic()
        ok = False
        try:
            pk, root, n, delta = await self.call(peer_id, "pospace_commitment",
                                                 timeout=self.challenge_timeout)
            # the commitment must be bound to the peer's ring identity: a node cannot
            # present someone else's plot.
            if node_id_from_pk(pk) != peer_id:
                ok = False
            else:
                i = self._rng.randrange(1, n)
                proof = await self.call(peer_id, "pospace_challenge", i,
                                        timeout=self.challenge_timeout)
                ok = verify_v3(root, pk, n, delta, i, proof)
        except Exception:
            ok = False
        elapsed = time.monotonic() - t0

        if ok:
            self.fail_counts[peer_id] = 0
        else:
            self.fail_counts[peer_id] = self.fail_counts.get(peer_id, 0) + 1
        fails = self.fail_counts[peer_id]
        self._log("challenge", peer_id, i, "pass" if ok else "fail", elapsed, fails)

        if fails >= MAX_FAILS:
            self._evict(peer_id)
        return ok

    async def challenge_round(self) -> None:
        """One periodic round: challenge our immediate successor.

        Driven externally in rounds (like stabilize/fix_fingers). Because every node
        challenges its successor, every live node is challenged by its predecessor over time.
        """
        succ = self.successor()
        if succ != self.node_id and self.net.is_up(succ):
            await self.challenge_peer(succ)

    def _evict(self, peer_id: int) -> None:
        """Remove a peer that failed too many challenges.

        In-process stand-in for distributed eviction: the challenger takes the peer offline so
        Chord's stabilize protocol heals the ring around it. Consensus-based eviction across
        the ring (so a single malicious challenger cannot evict an honest node) is a Phase 7
        concern and out of scope here.
        """
        self._log("evict", peer_id, -1, "evicted", 0.0, self.fail_counts.get(peer_id, 0))
        victim = self.net.nodes.get(peer_id)
        if victim is not None:
            victim.stop()
        self.successor_list = [s for s in self.successor_list if s != peer_id] or [self.node_id]
        self.fail_counts.pop(peer_id, None)

    # ---------- membership protocol (admission-gated) ----------
    async def create(self) -> None:
        """Start a new ring alone. The founder is admitted by fiat (no peer to challenge it)."""
        self._build_plot()
        self.predecessor = None
        self.successor_list = [self.node_id]
        self.start()
        self._log("join_admit", self.node_id, -1, "genesis", 0.0, 0)

    async def join(self, bootstrap_id: int) -> None:
        """Join an existing ring, gated on passing one challenge from our successor."""
        self._build_plot()
        self.predecessor = None
        self.start()
        succ, _hops = await self.call(bootstrap_id, "find_successor", self.node_id)
        try:
            admitted = await self.call(succ, "admit_peer", timeout=self.challenge_timeout)
        except Exception:
            admitted = False
        if not admitted:
            self._log("join_refused", succ, -1, "refused", 0.0, 0)
            self.stop()
            raise AdmissionError(f"node {self.node_id:#x} failed admission at {succ:#x}")
        self.successor_list = [succ]
        await self._refresh_successor_list()
        self._log("join_admit", succ, -1, "admitted", 0.0, 0)

    # ---------- logging ----------
    def _log(self, event: str, peer: int, index: int, result: str,
             elapsed: float, fails: int) -> None:
        append_row(POSPACE_CSV, POSPACE_HEADER,
                   [now_iso(), event, f"{self.node_id:#x}", f"{peer:#x}",
                    index, result, f"{elapsed:.6f}", fails])


class PoSpaceNode(PoSpaceMixin):
    """Concrete node = Chord + storage + DNS + query + ledger + PoSpace admission."""
    pass
