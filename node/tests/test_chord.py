"""Test for sub-issue #9 — Chord basics.

5 nodes form a ring; find_successor returns the correct node for several keys; finger
tables are populated. Ground truth is a brute-force successor over the sorted node IDs.
"""
import asyncio
import random

from node.chord import ChordNode, M
from node.net import Network
from node.ids import RING_SIZE
from node.tests.util import build_ring, expected_successor, ring_is_consistent, pk_for


async def _run() -> None:
    net = Network()
    nodes = await build_ring(ChordNode, net, n=5)
    node_ids = [nd.node_id for nd in nodes]

    # (1) ring is consistent: every node's successor is the true next node
    assert ring_is_consistent(nodes), "ring did not converge to a consistent successor cycle"

    # (2) successor list has the required length 3
    for nd in nodes:
        assert len(nd.successor_list) == 3, f"successor list len {len(nd.successor_list)} != 3"

    # (3) find_successor matches brute-force ground truth for many keys, from every node
    rng = random.Random(12345)
    checks = 0
    for _ in range(200):
        key = rng.randrange(RING_SIZE)
        want = expected_successor(key, node_ids)
        origin = rng.choice(nodes)
        got, hops = await origin.find_successor(key)
        assert got == want, f"find_successor({key:#x}) from {origin.node_id:#x}: got {got:#x} want {want:#x}"
        assert hops >= 0
        checks += 1

    # also exactly-on-node-id keys resolve to that node
    for nd in nodes:
        got, _ = await nodes[0].find_successor(nd.node_id)
        assert got == nd.node_id

    # (4) finger tables are populated (not all self)
    for nd in nodes:
        distinct = {f for f in nd.fingers}
        assert distinct != {nd.node_id}, "finger table never populated (all self)"
        # every finger must be a real ring member
        assert distinct.issubset(set(node_ids)), "finger points at a non-member"

    for nd in nodes:
        nd.stop()
    print(f"test_chord: PASS  (5 nodes, {checks} lookups correct, successor lists len 3, "
          f"fingers populated over M={M})")


def test_chord():
    asyncio.run(_run())


if __name__ == "__main__":
    test_chord()
