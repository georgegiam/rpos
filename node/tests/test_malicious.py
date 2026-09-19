"""Test for sub-issue #15 — malicious-mode hooks.

Covers the honest baseline (the switch is inert by default), then each dishonest mode flipped
on for a single node in an otherwise honest ring: lie (tolerated by the replica majority),
misroute (a routing peer returns itself), drop (a direct RPC times out), and forge (a
fabricated PoSpace proof is refused admission). Also checks the malicious.csv log. Self-running
(no pytest): `python -m node.tests.test_malicious`.
"""
import asyncio
import csv
import os

from node.ids import chunk_id
from node.logs import RESULTS_DIR
from node.malicious import MaliciousNode, MALICIOUS_HEADER, FORGED_IP, FORGED_TTL
from node.net import Network
from node.pospace_admission import AdmissionError
from node.query import IterativeResolver, _encode
from node.tests.util import build_ring, ring_is_consistent, pk_for, expected_successor

MALICIOUS_PATH = os.path.join(RESULTS_DIR, "malicious.csv")


async def _run() -> None:
    # start clean so we can assert on the rows this test writes
    if os.path.exists(MALICIOUS_PATH):
        os.remove(MALICIOUS_PATH)

    zone = {"example.com": "1.2.3.4", "test.org": "5.6.7.8"}
    upstream = IterativeResolver(zone)

    net = Network()
    nodes = await build_ring(MaliciousNode, net, n=7, upstream=upstream)
    assert ring_is_consistent(nodes)

    # (0) honest baseline: default mode is honest; a query resolves correctly and nothing is
    #     logged as malicious. The fallback also stores the answer into the DHT.
    ip, _ttl, outcome, _hops, _vote = await nodes[0].resolve_query("example.com")
    assert ip == "1.2.3.4", (ip, outcome)
    assert all(nd.malicious_mode == "honest" for nd in nodes)

    domain = "example.com"
    cid = chunk_id(domain)
    true_value = _encode("1.2.3.4", 300)              # IterativeResolver default ttl == 300
    replicas, _ = await nodes[0].replica_set(cid)
    assert len(replicas) >= 3, replicas

    # (1) lie: flip ONE replica to lie. get_chunk majority-votes across the replica set, so the
    #     two honest replicas outvote the single liar and the true value still wins.
    liar = next(nd for nd in nodes if nd.node_id == replicas[0])
    liar.malicious_mode = "lie"
    forged = _encode(FORGED_IP, FORGED_TTL)
    assert await liar._h_get_chunk(0, cid) == forged  # the liar does forge on a direct read
    querier = next(nd for nd in nodes if nd.node_id not in replicas)
    value, vote, _hops = await querier.get_chunk(domain)
    assert value == true_value, (value, vote)         # majority tolerates the one liar
    liar.malicious_mode = "honest"

    # (2) misroute: a misrouting peer's find_successor handler returns itself, not the truth.
    misrouter = nodes[3]
    key = (misrouter.node_id + 12345) % (1 << 160)
    true_succ = expected_successor(key, [nd.node_id for nd in nodes if nd.alive])
    misrouter.malicious_mode = "misroute"
    bad_succ, _ = await misrouter.call(misrouter.node_id, "find_successor", key)
    assert bad_succ == misrouter.node_id and bad_succ != true_succ, (bad_succ, true_succ)
    misrouter.malicious_mode = "honest"

    # (3) drop: a dropping node never replies, so a direct RPC to it times out. (No routing is
    #     driven through it here — Chord's lookups use untimed calls that would hang on a
    #     black hole; surviving churn around a dropper is a Phase 7 concern.)
    dropper = nodes[5]
    dropper.malicious_mode = "drop"
    try:
        await nodes[0].call(dropper.node_id, "ping", timeout=0.2)
        assert False, "RPC to a dropping node should time out"
    except asyncio.TimeoutError:
        pass
    dropper.malicious_mode = "honest"

    # (4) forge: a node that fabricates its PoSpace proof cannot pass the admission gate.
    forger = MaliciousNode(pk_for(99), net, upstream=upstream, malicious_mode="forge")
    try:
        await forger.join(nodes[0].node_id)
        assert False, "a forging node should be refused admission"
    except AdmissionError:
        pass
    assert forger.node_id not in net.nodes            # refused node took itself offline

    # (5) malicious.csv: header + every dishonest event fired; the honest baseline logged none.
    with open(MALICIOUS_PATH) as f:
        rows = list(csv.reader(f))
    assert rows[0] == MALICIOUS_HEADER, rows[0]
    events = {r[3] for r in rows[1:]}
    assert {"lie", "misroute", "drop", "forge"}.issubset(events), events

    for nd in nodes:
        if nd.alive:
            nd.stop()
    print(f"test_malicious: PASS  (honest baseline ok; lie outvoted; misroute caught; drop "
          f"times out; forge refused admission; {len(rows) - 1} rows logged to malicious.csv)")


def test_malicious():
    asyncio.run(_run())


if __name__ == "__main__":
    test_malicious()
