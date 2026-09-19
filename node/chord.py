"""Sub-issue #9 — Chord DHT basics.

A ChordNode over the in-process message bus (node/net.py). Implements the standard Chord
operations: join, find_successor, stabilize, fix_fingers, notify, plus a successor list of
length 3 for robustness to a single node leaving.

Node ID = SHA-256(pk) reduced into the 160-bit ring (see node/ids.py). All routing state is
maintained by the periodic stabilize/fix_fingers protocol exactly as in Stoica et al. (2001).

Transport is in-process (asyncio queues); Phase 3 swaps it for sockets. No real networking.
"""
import asyncio

from node.ids import RING_BITS, RING_SIZE, in_interval
from node.net import NodeServer, Network

SUCC_LIST_LEN = 3          # successor list length (acceptance criterion)
M = RING_BITS              # number of finger-table entries


class ChordNode(NodeServer):
    def __init__(self, pk: bytes, net: Network):
        super().__init__(pk, net)
        self.predecessor: int | None = None
        self.successor_list: list[int] = [self.node_id]   # [0] is the immediate successor
        self.fingers: list[int] = [self.node_id] * M
        self._next_finger = 0

        # Chord RPC surface
        self.register("get_successor", self._h_get_successor)
        self.register("get_predecessor", self._h_get_predecessor)
        self.register("get_succ_list", self._h_get_succ_list)
        self.register("closest_preceding", self._h_closest_preceding)
        self.register("find_successor", self._h_find_successor)
        self.register("notify", self._h_notify)
        self.register("ping", self._h_ping)

    # ---------- small accessors ----------
    def successor(self) -> int:
        return self.successor_list[0]

    # ---------- RPC handlers ----------
    async def _h_ping(self, src):
        return True

    async def _h_get_successor(self, src):
        return self.successor()

    async def _h_get_predecessor(self, src):
        return self.predecessor

    async def _h_get_succ_list(self, src):
        return list(self.successor_list)

    async def _h_closest_preceding(self, src, key):
        return self.closest_preceding(key)

    async def _h_find_successor(self, src, key):
        return await self.find_successor(key)

    async def _h_notify(self, src, nid):
        self._notify(nid)
        return True

    # ---------- routing ----------
    def closest_preceding(self, key: int) -> int:
        """Highest node in our tables that strictly precedes `key` on the ring."""
        for f in reversed(self.fingers):
            if f != self.node_id and in_interval(f, self.node_id, key):
                return f
        for s in reversed(self.successor_list):
            if s != self.node_id and in_interval(s, self.node_id, key):
                return s
        return self.node_id

    async def _succ_of(self, n: int) -> int:
        if n == self.node_id:
            return self.successor()
        return await self.call(n, "get_successor")

    async def _cpn_of(self, n: int, key: int) -> int:
        if n == self.node_id:
            return self.closest_preceding(key)
        return await self.call(n, "closest_preceding", key)

    async def find_successor(self, key: int) -> tuple[int, int]:
        """Iterative Chord lookup. Returns (successor_id, hops)."""
        n = self.node_id
        hops = 0
        while True:
            n_succ = await self._succ_of(n)
            if in_interval(key, n, n_succ, inc_right=True) or n == n_succ:
                return n_succ, hops
            nxt = await self._cpn_of(n, key)
            if nxt == n:
                return n_succ, hops
            n = nxt
            hops += 1
            if hops > M + SUCC_LIST_LEN + 4:      # safety valve against a transient loop
                return n_succ, hops

    # ---------- membership protocol ----------
    async def create(self) -> None:
        """Start a new ring alone."""
        self.predecessor = None
        self.successor_list = [self.node_id]
        self.start()

    async def join(self, bootstrap_id: int) -> None:
        """Join an existing ring via a known bootstrap node."""
        self.predecessor = None
        self.start()
        succ, _hops = await self.call(bootstrap_id, "find_successor", self.node_id)
        self.successor_list = [succ]
        await self._refresh_successor_list()

    def _notify(self, nid: int) -> None:
        if self.predecessor is None or not self.net.is_up(self.predecessor) \
                or in_interval(nid, self.predecessor, self.node_id):
            self.predecessor = nid

    async def _refresh_successor_list(self) -> None:
        """Rebuild the successor list from the immediate (live) successor's own list."""
        # drop any dead entries first
        alive = [s for s in self.successor_list if s == self.node_id or self.net.is_up(s)]
        self.successor_list = alive or [self.node_id]
        succ = self.successor()
        if succ == self.node_id:
            return
        try:
            their = await self.call(succ, "get_succ_list", timeout=2.0)
        except Exception:
            # successor is gone; promote the next live one and retry once
            self.successor_list = [s for s in self.successor_list if s != succ] or [self.node_id]
            return
        merged = [succ] + [s for s in their if s != self.node_id]
        deduped: list[int] = []
        for s in merged:
            if s not in deduped:
                deduped.append(s)
        self.successor_list = deduped[:SUCC_LIST_LEN] or [self.node_id]

    async def stabilize(self) -> None:
        """Verify our immediate successor and tell it about us."""
        succ = self.successor()
        try:
            x = await self.call(succ, "get_predecessor", timeout=2.0)
        except Exception:
            # successor down: drop it, promote next, and stop this round
            self.successor_list = [s for s in self.successor_list if s != succ] or [self.node_id]
            return
        # When succ == self the node is (or thinks it is) alone: the open interval (n, n)
        # spans the whole ring, so any real predecessor becomes our successor.
        if x is not None and x != self.node_id and self.net.is_up(x) \
                and (succ == self.node_id or in_interval(x, self.node_id, succ)):
            self.successor_list[0] = x
        await self._refresh_successor_list()
        succ = self.successor()
        if succ != self.node_id:
            try:
                await self.call(succ, "notify", self.node_id, timeout=2.0)
            except Exception:
                pass

    async def fix_fingers(self) -> None:
        """Refresh one finger per call (round-robins through all M entries)."""
        self._next_finger = (self._next_finger + 1) % M
        start = (self.node_id + (1 << self._next_finger)) % RING_SIZE
        try:
            succ, _ = await self.find_successor(start)
            self.fingers[self._next_finger] = succ
        except Exception:
            pass

    async def check_predecessor(self) -> None:
        if self.predecessor is not None and not self.net.is_up(self.predecessor):
            self.predecessor = None
