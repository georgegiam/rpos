"""Sub-issue #15 — malicious-mode hooks.

A MaliciousNode is a full resolver node (Chord + storage + DNS + query + ledger + PoSpace
admission) with one extra per-node config flag, MALICIOUS_MODE, chosen at construction:

    honest    — behave exactly like PoSpaceNode (the default; nothing changes)
    lie       — as a chunk replica, return a forged answer on reads
    drop       — silently ignore every inbound RPC (a black hole)
    misroute   — as a routing peer, return a wrong successor to poison lookups
    forge      — present a fabricated PoSpace proof to try to pass admission without a plot

The behaviours are wired in here but INACTIVE by default (honest). Actually running the
attacks across adversary fractions and producing result graphs is Phase 7 (experiments
B1–B7); this module only lands the switch and the plumbing so those runs have something to
flip on.

Design: MaliciousMixin sits at the *top* of the node's MRO, ahead of PoSpaceMixin. Because it
resolves first, its overrides of specific RPC handlers win automatically — and since each
layer registers its handlers as ``self._h_xxx`` on the concrete instance, the malicious
versions are what actually get registered, with no change to the existing registration calls.
Every override reads ``self.malicious_mode`` and, when "honest", delegates to ``super()``, so
the honest path is byte-identical to PoSpaceNode. The flag is a plain attribute read at call
time, so a test (or Phase 7 driver) can flip a single node in an otherwise honest ring with
``node.malicious_mode = "lie"``.

drop is the one behaviour that is not a handler override — it must skip *replying*. It uses the
honest-inert ``NodeServer._should_drop`` hook (node/net.py), overridden here.

In-process transport only (Phase 3 swaps in sockets).
"""
from node.logs import append_row, now_iso
from node.pospace_admission import PoSpaceMixin
from node.query import _encode

MODES = ("honest", "lie", "drop", "misroute", "forge")

MALICIOUS_CSV = "malicious.csv"
MALICIOUS_HEADER = ["timestamp", "node", "mode", "event", "detail"]

FORGED_IP = "6.6.6.6"        # the attacker IP a "lie" node substitutes
FORGED_TTL = 300


class MaliciousMixin:
    """Top-of-MRO mixin adding the MALICIOUS_MODE switch and the four dishonest behaviours."""

    def __init__(self, pk: bytes, net, malicious_mode: str = "honest", **kwargs):
        if malicious_mode not in MODES:
            raise ValueError(f"malicious_mode must be one of {MODES}, got {malicious_mode!r}")
        self.malicious_mode = malicious_mode
        # consume our own kwarg; everything else flows on to PoSpaceMixin and below
        super().__init__(pk, net, **kwargs)

    # ---------- drop: transport-level hook (node/net.py) ----------
    def _should_drop(self, method: str) -> bool:
        if self.malicious_mode == "drop":
            self._mlog("drop", method)
            return True
        return False

    # ---------- lie: forge answers as a chunk replica (storage.py) ----------
    async def _h_get_chunk(self, src, cid: int):
        if self.malicious_mode == "lie":
            forged = _encode(FORGED_IP, FORGED_TTL)
            self._mlog("lie", f"cid={cid:#x} -> {forged}")
            return forged
        return await super()._h_get_chunk(src, cid)

    # ---------- misroute: return a wrong successor (chord.py) ----------
    async def _h_find_successor(self, src, key: int):
        if self.malicious_mode == "misroute":
            self._mlog("misroute", f"key={key:#x}")
            return self.node_id, 0        # claim to be the successor of everything
        return await super()._h_find_successor(src, key)

    async def _h_closest_preceding(self, src, key: int):
        if self.malicious_mode == "misroute":
            self._mlog("misroute", f"cpn key={key:#x}")
            return self.node_id           # send the querier back to us, stalling its walk
        return await super()._h_closest_preceding(src, key)

    # ---------- forge: fabricate a PoSpace proof (pospace_admission.py) ----------
    async def _h_challenge(self, src, i: int):
        if self.malicious_mode == "forge":
            self._mlog("forge", f"i={i}")
            # a proof is {idx: (label, path)}; this one has the wrong key set and an empty
            # path, so the challenger's verify_v3 rejects it (no real plot required).
            return {i: (b"\x00" * 32, [])}
        return await super()._h_challenge(src, i)

    # ---------- logging ----------
    def _mlog(self, event: str, detail: str) -> None:
        """Log one row when a dishonest action actually fires (honest path writes nothing)."""
        append_row(MALICIOUS_CSV, MALICIOUS_HEADER,
                   [now_iso(), f"{self.node_id:#x}", self.malicious_mode, event, detail])


class MaliciousNode(MaliciousMixin, PoSpaceMixin):
    """Full resolver node with the MALICIOUS_MODE switch (default honest)."""
    pass
