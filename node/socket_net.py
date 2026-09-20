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

Wire codec. Length-prefixed **type-tagged JSON** (a *data-only* format). Unlike pickle, the
decoder can construct nothing but a fixed set of primitives, so a hostile frame can neither
execute code nor instantiate arbitrary objects — which matters because Phase 7 puts a
malicious node on this wire and the transport itself must not be an attack surface. The tags
round-trip every payload these handlers use with no loss of type: big ints (JSON keeps them
exact — the ring is 160-bit, well past msgpack's 64-bit limit, which is why plain JSON and not
msgpack), None, bool, float, str, bytes (base64), tuples (kept distinct from lists so
``tag, payload = ...`` unpacking still works), lists, and dicts with non-string keys such as
the PoSpace proof ``dict[int, (bytes, list[bytes])]``. Anything that is not one of these types
is refused at encode time rather than silently coerced, so the transport still cannot corrupt
a security measurement by mis-typing a value.

Frame bound. A hard ``MAX_FRAME_BYTES`` cap is enforced on both directions. An inbound header
announcing more than the cap is rejected *before* the body is read, so a peer can never make a
node buffer an unbounded frame; ``readexactly`` then bounds the actual read to the announced
(capped) length. This closes the memory-exhaustion vector a raw length prefix would otherwise
open. The application-layer adversary behaviours (lie / drop / misroute / forge — see
node/malicious.py) remain modelled ABOVE the transport, in the node's own handlers.
"""
import asyncio
import base64
import json
import time
from typing import Any, Optional

# Hard cap on any single frame. Legitimate payloads (PoSpace proofs a few KiB, DNS chunks,
# ledger logs) are far below this; the cap exists only to stop a hostile/buggy peer announcing
# a huge length and exhausting memory. Oversized frames are rejected, never buffered.
MAX_FRAME_BYTES = 8 * 1024 * 1024


class RemoteError(Exception):
    """Raised on the caller side when the remote handler raised. Callers already treat any
    Exception from an RPC as a failure (drop/timeout/bad-vote), so a generic error preserves
    the in-process behaviour where the original exception object propagated back."""


class FrameError(Exception):
    """A frame was oversized or malformed. Treated as a connection failure: the socket is
    dropped without buffering, so a peer cannot exhaust memory or smuggle non-data values."""


def _enc(obj: Any) -> Any:
    """Encode a data value into a JSON-safe, self-describing form.

    Only the payload types these RPC handlers actually use are accepted; anything else raises.
    That refusal is the point of a data-only wire: decoding (``_dec``) can rebuild nothing but
    these primitives, so a crafted frame cannot execute code or build arbitrary objects.
    """
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj                                    # JSON preserves big ints exactly
    if isinstance(obj, (bytes, bytearray)):
        return {"b": base64.b64encode(bytes(obj)).decode("ascii")}
    if isinstance(obj, tuple):
        return {"t": [_enc(x) for x in obj]}
    if isinstance(obj, list):
        return [_enc(x) for x in obj]
    if isinstance(obj, dict):
        return {"d": [[_enc(k), _enc(v)] for k, v in obj.items()]}
    raise FrameError(f"non-data value of type {type(obj).__name__!r} cannot be sent")


def _dec(obj: Any) -> Any:
    """Inverse of ``_enc``. Bare JSON scalars pass through; a JSON object is only ever one of
    our tag wrappers, so an unrecognised object shape is rejected rather than trusted."""
    if isinstance(obj, list):
        return [_dec(x) for x in obj]
    if isinstance(obj, dict):
        if "b" in obj:
            return base64.b64decode(obj["b"])
        if "t" in obj:
            return tuple(_dec(x) for x in obj["t"])
        if "d" in obj:
            return {_dec(k): _dec(v) for k, v in obj["d"]}
        raise FrameError("unrecognised object tag on the wire")
    return obj


async def _read_frame(reader: asyncio.StreamReader) -> Any:
    header = await reader.readexactly(4)
    n = int.from_bytes(header, "big")
    if n > MAX_FRAME_BYTES:                            # reject BEFORE allocating/reading the body
        raise FrameError(f"frame of {n} bytes exceeds cap {MAX_FRAME_BYTES}")
    body = await reader.readexactly(n)                 # bounded read: at most the capped length
    return _dec(json.loads(body.decode("utf-8")))


async def _write_frame(writer: asyncio.StreamWriter, obj: Any) -> None:
    body = json.dumps(_enc(obj), separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise FrameError(f"outbound frame of {len(body)} bytes exceeds cap {MAX_FRAME_BYTES}")
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
        except (asyncio.IncompleteReadError, ConnectionError, FrameError):
            # peer vanished, or sent an oversized/malformed frame — drop it, don't buffer.
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
