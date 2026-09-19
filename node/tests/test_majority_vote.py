"""Check 2 — majority-vote defence against a lying replica.

A 5-node ring stores one DNS record. One of that record's replicas is flipped to
MALICIOUS_MODE="lie", so on a read it returns a forged answer. The read path
(StorageMixin.get_chunk) reads every reachable replica and returns the majority value; the
two honest replicas must outvote the single liar, so the honest answer wins.

The test asserts explicitly and fails loudly if the forged value is ever returned. Self-running
(no pytest): `python -m node.tests.test_majority_vote`.
"""
import asyncio

from node.ids import chunk_id
from node.malicious import MaliciousNode, FORGED_IP, FORGED_TTL
from node.net import Network
from node.query import IterativeResolver, _encode, _decode
from node.tests.util import build_ring, ring_is_consistent

HONEST_IP = "1.2.3.4"
DOMAIN = "example.com"


async def _run() -> None:
    zone = {DOMAIN: HONEST_IP}
    upstream = IterativeResolver(zone, ttl=300)          # IterativeResolver default ttl
    honest_value = _encode(HONEST_IP, 300)
    forged_value = _encode(FORGED_IP, FORGED_TTL)

    net = Network()
    nodes = await build_ring(MaliciousNode, net, n=5, upstream=upstream)
    assert ring_is_consistent(nodes), "ring did not converge"
    assert all(nd.malicious_mode == "honest" for nd in nodes), "nodes not honest at start"

    # --- store the record: a fallback resolve writes it to the s replicas ---
    ip, _ttl, outcome, _hops, vote = await nodes[0].resolve_query(DOMAIN)
    assert ip == HONEST_IP and outcome == "fallback", (ip, outcome)

    cid = chunk_id(DOMAIN)
    replicas, _ = await nodes[0].replica_set(cid)
    assert len(replicas) >= 3, f"need >=3 replicas for a majority to defend, got {replicas}"

    # --- flip ONE replica to lie ---
    liar = next(nd for nd in nodes if nd.node_id == replicas[0])
    liar.malicious_mode = "lie"

    # sanity: the liar really does forge on a direct read (so the defence is non-trivial)
    direct = await liar._h_get_chunk(0, cid)
    assert direct == forged_value, f"liar did not forge on direct read: {direct!r}"

    # --- read through the majority-vote path from a NON-replica node ---
    querier = next(nd for nd in nodes if nd.node_id not in replicas)
    value, vote, _hops = await querier.get_chunk(DOMAIN)

    # --- the assertions that make this a real defence test ---
    assert value is not None, "no replica answered"
    assert value != forged_value, (
        f"MAJORITY VOTE FAILED: forged answer {forged_value!r} was returned (vote={vote})")
    assert value == honest_value, (
        f"MAJORITY VOTE FAILED: expected honest {honest_value!r}, got {value!r} (vote={vote})")
    got_ip, _ = _decode(value)
    assert got_ip == HONEST_IP and got_ip != FORGED_IP, got_ip

    for nd in nodes:
        if nd.alive:
            nd.stop()
    print(f"test_majority_vote: PASS  (1 liar in {len(replicas)} replicas outvoted; "
          f"returned honest {HONEST_IP}, not forged {FORGED_IP}; vote={vote})")


def test_majority_vote() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    test_majority_vote()
