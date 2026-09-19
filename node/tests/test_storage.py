"""Test for sub-issue #10 — chunk storage + replication.

10 domains stored over 5 nodes with s=3 replication; retrieval is correct, and stays
correct when one replica is corrupted to return a wrong value (majority vote wins).
"""
import asyncio

from node.storage import StorageNode, S
from node.net import Network
from node.ids import chunk_id
from node.tests.util import build_ring


DOMAINS = [f"host{i}.example.com" for i in range(10)]


async def _run() -> None:
    net = Network()
    nodes = await build_ring(StorageNode, net, n=5)
    by_id = {nd.node_id: nd for nd in nodes}

    # store 10 domains, each from an arbitrary origin node
    for i, d in enumerate(DOMAINS):
        origin = nodes[i % len(nodes)]
        written, hops = await origin.store_chunk(d, f"93.184.216.{i}")
        assert len(written) == S, f"{d}: wrote {len(written)} replicas, want {S}"

    # clean retrieval from an arbitrary origin
    for i, d in enumerate(DOMAINS):
        origin = nodes[(i + 2) % len(nodes)]
        val, vote, _ = await origin.get_chunk(d)
        assert val == f"93.184.216.{i}", f"{d}: got {val!r}"
        assert vote == "3/3", f"{d}: vote {vote} before corruption"

    # corrupt ONE replica of one domain, then confirm majority vote still returns truth
    d0 = DOMAINS[0]
    cid = chunk_id(d0)
    replicas, _ = await nodes[0].replica_set(cid)
    victim = by_id[replicas[0]]
    victim.store[cid] = "6.6.6.6"                 # a lie in one of three replicas
    val, vote, _ = await nodes[3].get_chunk(d0)
    assert val == "93.184.216.0", f"majority vote failed under corruption: {val!r}"
    assert vote == "2/3", f"expected 2/3 agreement, got {vote}"

    for nd in nodes:
        nd.stop()
    print(f"test_storage: PASS  (10 domains x s={S} over 5 nodes; majority vote survived "
          f"one corrupted replica, vote {vote})")


def test_storage():
    asyncio.run(_run())


if __name__ == "__main__":
    test_storage()
