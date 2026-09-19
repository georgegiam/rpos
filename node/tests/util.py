"""Shared helpers for the Phase 2 self-running tests."""
import asyncio

from node.ids import RING_SIZE, in_interval


def pk_for(i: int) -> bytes:
    """Deterministic 33-byte public key for test node i (fixed seed => reproducible ring)."""
    return b"node-pk-" + i.to_bytes(4, "big") + b"\x00" * 21


async def build_ring(NodeClass, net, n: int, rounds: int = 40, **kwargs):
    """Create n nodes, join them into one ring, and run the stabilize protocol to convergence."""
    nodes = [NodeClass(pk_for(i), net, **kwargs) for i in range(n)]
    await nodes[0].create()
    for nd in nodes[1:]:
        await nd.join(nodes[0].node_id)
        await run_protocol(nodes, rounds=6)
    await run_protocol(nodes, rounds=rounds)
    return nodes


async def run_protocol(nodes, rounds: int = 20):
    """Run several rounds of stabilize + fix_fingers + check_predecessor over all live nodes."""
    for _ in range(rounds):
        for nd in nodes:
            if nd.alive:
                await nd.stabilize()
        for nd in nodes:
            if nd.alive:
                await nd.fix_fingers()
                await nd.check_predecessor()
        await asyncio.sleep(0)


def expected_successor(key: int, node_ids: list[int]) -> int:
    """Brute-force ground truth: the first node ID >= key on the ring (wrapping)."""
    live = sorted(set(node_ids))
    for nid in live:
        if nid >= key:
            return nid
    return live[0]


def ring_is_consistent(nodes) -> bool:
    """Every live node's immediate successor is the true next node on the ring."""
    live = sorted(nd.node_id for nd in nodes if nd.alive)
    ok = True
    for nd in nodes:
        if not nd.alive:
            continue
        idx = live.index(nd.node_id)
        true_succ = live[(idx + 1) % len(live)]
        if nd.successor() != true_succ:
            ok = False
    return ok
