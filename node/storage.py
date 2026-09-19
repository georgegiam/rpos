"""Sub-issue #10 — chunk storage + replication.

A StorageMixin layered on top of ChordNode. A domain maps to a chunk ID
(SHA-256(domain) mod 2**160); the chunk lives on the responsible node (the successor of
the chunk ID) and is replicated to the next s-1 successors, so s=3 copies exist. Retrieval
reads all reachable replicas and returns the majority value, which tolerates one replica
returning a wrong (or no) value.

In-process transport only. Values are opaque strings (a DNS record set, later).
"""
from collections import Counter

from node.chord import ChordNode
from node.ids import chunk_id
from node.net import Network

S = 3          # replication factor (acceptance criterion)


class StorageMixin(ChordNode):
    def __init__(self, pk: bytes, net: Network, replication: int = S, **kwargs):
        super().__init__(pk, net, **kwargs)
        self.replication = replication
        self.store: dict[int, str] = {}          # chunk_id -> value
        self.register("put_chunk_local", self._h_put_chunk)
        self.register("get_chunk_local", self._h_get_chunk)

    # ---------- RPC handlers ----------
    async def _h_put_chunk(self, src, cid: int, value: str):
        self.store[cid] = value
        return True

    async def _h_get_chunk(self, src, cid: int):
        return self.store.get(cid)

    # ---------- replica-set resolution ----------
    async def replica_set(self, cid: int) -> tuple[list[int], int]:
        """Return (list of up to s node IDs holding the chunk, hops to find the primary)."""
        primary, hops = await self.find_successor(cid)
        nodes = [primary]
        try:
            slist = await self.call(primary, "get_succ_list", timeout=2.0)
        except Exception:
            slist = []
        for s in slist:
            if s not in nodes:
                nodes.append(s)
            if len(nodes) >= self.replication:
                break
        return nodes[: self.replication], hops

    # ---------- store / retrieve ----------
    async def store_chunk(self, domain: str, value: str) -> tuple[list[int], int]:
        """Write `value` for `domain` to every replica. Returns (replicas_written, hops)."""
        cid = chunk_id(domain)
        replicas, hops = await self.replica_set(cid)
        written = []
        for nid in replicas:
            try:
                await self.call(nid, "put_chunk_local", cid, value, timeout=2.0)
                written.append(nid)
            except Exception:
                pass
        return written, hops

    async def get_chunk(self, domain: str) -> tuple[str | None, str, int]:
        """Read all reachable replicas and majority-vote. Returns (value, vote, hops).

        `vote` is "<agree>/<responses>"; value is None if no replica answered.
        """
        cid = chunk_id(domain)
        replicas, hops = await self.replica_set(cid)
        values: list[str] = []
        for nid in replicas:
            try:
                v = await self.call(nid, "get_chunk_local", cid, timeout=2.0)
            except Exception:
                continue
            if v is not None:
                values.append(v)
        if not values:
            return None, "0/0", hops
        value, agree = Counter(values).most_common(1)[0]
        return value, f"{agree}/{len(values)}", hops


class StorageNode(StorageMixin):
    """Concrete node = Chord + storage (used by tests for this sub-issue)."""
    pass
