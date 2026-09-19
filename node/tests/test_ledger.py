"""Test for sub-issue #13 — chunk ledger (Algorithm 3).

Covers the two-phase commit (commit + abort paths), the tamper-evident hash-chained log,
TTL-driven refresh through the ledger, and that updates.csv is written with the required
columns. Self-running (no pytest): `python -m node.tests.test_ledger`.
"""
import asyncio
import csv
import os
import time

from node.ledger import LedgerNode
from node.query import IterativeResolver, _encode
from node.net import Network
from node.ids import chunk_id
from node.logs import RESULTS_DIR
from node.tests.util import build_ring

UPDATES_PATH = os.path.join(RESULTS_DIR, "updates.csv")


async def _run() -> None:
    # start clean so we can assert on the rows this test writes
    if os.path.exists(UPDATES_PATH):
        os.remove(UPDATES_PATH)

    zone = {"example.com": "93.184.216.34", "iana.org": "192.0.43.8"}
    upstream = IterativeResolver(zone, ttl=120)
    net = Network()
    nodes = await build_ring(LedgerNode, net, n=5, upstream=upstream)
    by_id = {nd.node_id: nd for nd in nodes}

    # (1) two-phase commit: propose an update and confirm it lands on a majority of replicas
    cid = chunk_id("example.com")
    replicas, _ = await nodes[0].replica_set(cid)
    majority = len(replicas) // 2 + 1
    value = _encode("93.184.216.34", 120)
    ok = await nodes[0].propose_update("example.com", value)
    assert ok is True, ok
    landed = sum(1 for nid in replicas if by_id[nid].store.get(cid) == value)
    assert landed >= majority, (landed, majority)

    # (2) hash chain is valid on a committing replica
    primary_id, _ = await nodes[0].find_successor(cid)
    primary = by_id[primary_id]
    assert primary.verify_chain()
    assert primary.ledger[-1]["action"] == "update"

    # (3) abort path: pre-lock a majority of a chunk's replicas for a foreign proposal, so
    #     pre-commit cannot reach a majority -> propose_update aborts and returns False
    cid2 = chunk_id("iana.org")
    replicas2, _ = await nodes[0].replica_set(cid2)
    for nid in replicas2[: len(replicas2) // 2 + 1]:
        by_id[nid].pending[cid2] = "foreign-pid"
    ok2 = await nodes[1].propose_update("iana.org", _encode("192.0.43.8", 120))
    assert ok2 is False, ok2

    # (4) TTL refresh: force the primary's copy to expire, then refresh through the ledger
    primary.expiry[cid] = time.monotonic() - 1
    refreshed = await primary.refresh_expired()
    assert ("example.com", True) in refreshed, refreshed
    assert primary.ledger[-1]["action"] == "ttl_refresh"
    assert primary.verify_chain()

    # (5) tamper-evidence: mutating any committed entry breaks the chain (do last)
    assert primary.verify_chain()
    primary.ledger[0]["value"] = "tampered"
    assert not primary.verify_chain()

    # (6) updates.csv exists with the required header and rows for every action/outcome
    with open(UPDATES_PATH) as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["timestamp", "domain", "action", "outcome"]
    actions = {r[2] for r in rows[1:]}
    outcomes = {r[3] for r in rows[1:]}
    assert {"update", "ttl_refresh"}.issubset(actions), actions
    assert {"committed", "aborted"}.issubset(outcomes), outcomes

    for nd in nodes:
        nd.stop()
    print(f"test_ledger: PASS  (2PC commit on {landed}/{len(replicas)} replicas, abort on lock, "
          f"TTL refresh via ledger, tamper detected, {len(rows) - 1} rows logged to updates.csv)")


def test_ledger():
    asyncio.run(_run())


if __name__ == "__main__":
    test_ledger()
