"""Real TCP socket transport for cross-container nodes (Phase 3, epic #24).

This is the network counterpart to the in-process bus in ``node/net.py``. It is ADDED
ALONGSIDE that bus, never replacing it: Phase 2 tests keep using ``Network`` (deterministic,
single-process); ``SocketNetwork`` is selected only by the container entrypoint
(``node/run_ring_node.py``) so nodes in separate containers form a real Chord ring over
sockets.

Design goal: swap ONLY the transport, nothing else. ``SocketNetwork`` exposes the exact same
surface the node code already calls — ``register_node`` / ``unregister_node`` / ``is_up`` /
``rpc`` / a ``.nodes`` dict / a ``.latency`` attr — so ``chord.py``, ``storage.py``,
``ledger.py``, ``query.py`` and ``pospace_admission.py`` run byte-identically on either
transport. That is what makes a nodes-mode measurement comparable to the in-process tests:
majority vote, the ledger 2PC, and PoSpace verify are the same code on both paths.

Addressing. Node references on the wire are bare ring IDs (ints), exactly as in-process. To
open a socket we resolve id -> (host, port) through a *roster* handed in at construction. In
the testbed the roster is fully derivable from N (deterministic pks -> ids, Docker-DNS peer
names), so it is a reproducible id->address map, NOT ring state: who-succeeds-whom is still
discovered dynamically by find_successor/stabilize/notify over these sockets.

Liveness. ``is_up(peer)`` is synchronous (Chord calls it mid-routing), so it cannot ping over
the network. Instead we keep a short-lived failure cache: an RPC that times out or refuses
marks the peer down for ``dead_ttl`` seconds; a success clears it. This gives Chord a usable
failure signal while letting a transiently-unreachable peer recover.

Wire codec. Length-prefixed **pickle**. Pickle round-trips every RPC payload these handlers
use — big ints, None, bool, str, bytes, tuples, lists, and the PoSpace proof
``dict[int, (bytes, list[bytes])]`` — with zero custom coding, so the transport can never
silently corrupt a security measurement by mis-typing a value. CAVEAT (flagged, not hidden):
pickle executes arbitrary code on load, so this transport trusts its peers at the wire level.
That is acceptable here because every peer is an instance of our own image on an isolated
bridge network, and the adversary behaviours in the threat model (lie / drop / misroute /
forge — see node/malicious.py) are modelled ABOVE the transport, in the node's own handlers.
A production deployment would use a hardened wire format (e.g. length-checked protobuf); that
is out of scope for the emulation harness and noted as a limitation.
"""
import asyncio
import pickle
import time
from typing import Any, Optional


class RemoteError(Exception):
    """Raised on the caller side when the remote handler raised. Callers already treat any
    Exception from an RPC as a failure (drop/timeout/bad-vote), so a generic error preserves
    the in-process behaviour where the original exception object propagated back."""


async def _read_frame(reader: asyncio.StreamReader) -> Any:
    header = await reader.readexactly(4)
    n = int.from_bytes(header, "big")
    body = await reader.readexactly(n)
    return pickle.loads(body)


async def _write_frame(writer: asyncio.StreamWriter, obj: Any) -> None:
    body = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
    writer.write(len(body).to_bytes(4, "big") + body)
    await writer.drain()


class SocketNetwork:
    """Transport-compatible drop-in for ``node.net.Network`` backed by TCP sockets.

    Parameters
    ----------
    self_id   : this node's ring id (so ``rpc`` can short-circuit self-calls defensively).
    roster    : {ring_id: (host, port)} for every peer, including this node.
    dead_ttl  : seconds a peer stays marked-down after a failed RPC before it may be retried.
    latency   : kept for interface parity with ``Network`` (real latency comes from tc netem).
    """

    def __init__(self, self_id: int, roster: dict[int, tuple[str, int]],
                 dead_ttl: float = 3.0, latency: float = 0.0):
        self.self_id = self_id
        self.roster = dict(roster)
        self.dead_ttl = dead_ttl
        self.latency = latency
        self.nodes: dict[int, Any] = {}          # local node only (parity with Network.nodes)
        self._local = None
        self._dead: dict[int, float] = {}         # peer_id -> monotonic time marked down
        self._server: Optional[asyncio.AbstractServer] = None

    # ---------- registry (parity with Network) ----------
    def register_node(self, node) -> None:
        self._local = node
        self.nodes[node.node_id] = node

    def unregister_node(self, node_id: int) -> None:
        self.nodes.pop(node_id, None)

    def is_up(self, node_id: int) -> bool:
        if node_id == self.self_id:
            return self._local is not None and self._local.alive
        if node_id not in self.roster:
            return False
        t = self._dead.get(node_id)
        if t is not None and (time.monotonic() - t) < self.dead_ttl:
            return False
        return True

    def _mark_up(self, node_id: int) -> None:
        self._dead.pop(node_id, None)

    def _mark_down(self, node_id: int) -> None:
        self._dead[node_id] = time.monotonic()

    # ---------- client side ----------
    async def rpc(self, src: int, dst: int, method: str, *args,
                  timeout: Optional[float] = None) -> Any:
        """Send an RPC to ``dst`` and await the reply. Mirrors Network.rpc's contract:
        raises on a down node, a timeout, or a remote handler error."""
        if dst == self.self_id:                    # defensive; node.call already shortcuts self
            return await self._local.handlers[method](src, *args)
        addr = self.roster.get(dst)
        if addr is None:
            raise ConnectionError(f"no address for node {dst:#x}")
        try:
            result = await asyncio.wait_for(self._do_rpc(src, dst, method, args, addr),
                                            timeout) if timeout is not None \
                else await self._do_rpc(src, dst, method, args, addr)
            self._mark_up(dst)
            return result
        except Exception:
            self._mark_down(dst)
            raise

    async def _do_rpc(self, src, dst, method, args, addr) -> Any:
        reader, writer = await asyncio.open_connection(*addr)
        try:
            await _write_frame(writer, ("REQ", src, method, args))
            tag, payload = await _read_frame(reader)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        if tag == "OK":
            return payload
        raise RemoteError(f"{method} @ {dst:#x}: {payload}")

    # ---------- server side ----------
    async def start_server(self, host: str, port: int) -> None:
        """Bind the RPC listener. Plays the role of NodeServer._serve for the socket path:
        each inbound connection carries one request, which we dispatch to the local node's
        registered handler (honouring the malicious 'drop' hook) and reply to."""
        self._server = await asyncio.start_server(self._on_conn, host, port)

    async def _on_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            tag, src, method, args = await _read_frame(reader)
            if tag != "REQ":
                return
            node = self._local
            # malicious 'drop': never reply (caller times out) — same semantics as the bus.
            if node is None or not node.alive or node._should_drop(method):
                return
            handler = node.handlers.get(method)
            try:
                if handler is None:
                    raise KeyError(f"no handler {method!r} on node {node.node_id:#x}")
                result = await handler(src, *args)
                await _write_frame(writer, ("OK", result))
            except Exception as e:
                await _write_frame(writer, ("ERR", repr(e)))
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def stop_server(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None
