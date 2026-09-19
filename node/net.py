"""In-process message bus that simulates network message passing with asyncio queues.

This is deliberately NOT real networking — Phase 3 replaces it with sockets. Each node
owns an inbox `asyncio.Queue`; an RPC enqueues a `Message` carrying a Future on the
destination's inbox and awaits the Future, which the destination's `serve()` loop resolves
by dispatching to a registered handler. This gives us realistic async, per-message delivery,
timeouts and drops, while staying single-process and deterministic under a fixed seed.

Handlers are coroutines registered by name on a node via `node.register(name, coro)`.
"""
import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class Message:
    src: int
    dst: int
    method: str
    args: tuple
    fut: asyncio.Future


class Network:
    """Registry of nodes keyed by ring ID, plus optional per-hop latency."""

    def __init__(self, latency: float = 0.0):
        self.nodes: dict[int, "NodeServer"] = {}
        self.latency = latency          # seconds added to each message delivery

    def register_node(self, node: "NodeServer") -> None:
        self.nodes[node.node_id] = node

    def unregister_node(self, node_id: int) -> None:
        self.nodes.pop(node_id, None)

    def is_up(self, node_id: int) -> bool:
        n = self.nodes.get(node_id)
        return n is not None and n.alive

    async def rpc(self, src: int, dst: int, method: str, *args, timeout: Optional[float] = None) -> Any:
        """Send an RPC from src to dst and await the reply. Raises on down node/timeout."""
        dst_node = self.nodes.get(dst)
        if dst_node is None or not dst_node.alive:
            raise ConnectionError(f"node {dst:#x} is down")
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        msg = Message(src=src, dst=dst, method=method, args=args, fut=fut)
        if self.latency:
            await asyncio.sleep(self.latency)
        await dst_node.inbox.put(msg)
        if timeout is not None:
            return await asyncio.wait_for(fut, timeout)
        return await fut


class NodeServer:
    """Base of every node: an inbox, a handler table, and a serve loop.

    Subclasses/mixins register handlers in their __init__ via self.register(...).
    """

    def __init__(self, pk: bytes, net: Network):
        from node.ids import node_id_from_pk
        self.pk = pk
        self.node_id = node_id_from_pk(pk)
        self.net = net
        self.alive = True
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.handlers: dict[str, Callable] = {}
        self._serve_task: Optional[asyncio.Task] = None
        net.register_node(self)

    def register(self, name: str, coro: Callable) -> None:
        self.handlers[name] = coro

    async def call(self, dst: int, method: str, *args, timeout: Optional[float] = None) -> Any:
        """Convenience: RPC from this node to another (local shortcut if dst == self)."""
        if dst == self.node_id:
            return await self.handlers[method](self.node_id, *args)
        return await self.net.rpc(self.node_id, dst, method, *args, timeout=timeout)

    def start(self) -> None:
        if self._serve_task is None:
            self._serve_task = asyncio.create_task(self._serve())

    async def _serve(self) -> None:
        while self.alive:
            msg = await self.inbox.get()
            if not self.alive:
                break
            handler = self.handlers.get(msg.method)
            try:
                if handler is None:
                    raise KeyError(f"no handler {msg.method!r} on node {self.node_id:#x}")
                result = await handler(msg.src, *msg.args)
                if not msg.fut.done():
                    msg.fut.set_result(result)
            except Exception as e:  # deliver the error back to the caller
                if not msg.fut.done():
                    msg.fut.set_exception(e)

    def stop(self) -> None:
        """Take the node offline (simulates leave/crash)."""
        self.alive = False
        self.net.unregister_node(self.node_id)
        if self._serve_task is not None:
            self._serve_task.cancel()
            self._serve_task = None
