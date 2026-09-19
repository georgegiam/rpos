"""Test for sub-issue #12 — query path (Algorithm 2).

Covers the three outcomes and the write-back-on-fallback behaviour, checks the majority
vote, and confirms queries.csv is written with the required columns.
"""
import asyncio
import csv
import os

from node.query import QueryNode, IterativeResolver
from node.net import Network
from node.ids import chunk_id
from node.logs import RESULTS_DIR
from node.tests.util import build_ring

QUERIES_PATH = os.path.join(RESULTS_DIR, "queries.csv")


async def _run() -> None:
    # start clean so we can assert on the rows this test writes
    if os.path.exists(QUERIES_PATH):
        os.remove(QUERIES_PATH)

    zone = {"example.com": "93.184.216.34", "iana.org": "192.0.43.8"}
    upstream = IterativeResolver(zone, ttl=120)
    net = Network()
    nodes = await build_ring(QueryNode, net, n=5, upstream=upstream)

    # (1) first query for example.com misses cache + DHT -> fallback, and writes back
    ip, ttl, outcome, hops, vote = await nodes[0].resolve_query("example.com")
    assert (ip, ttl, outcome) == ("93.184.216.34", 120, "fallback"), (ip, ttl, outcome)
    assert vote.startswith("stored:3")

    # the answer is now in the DHT: a different origin gets a dht_hit with full agreement
    ip, ttl, outcome, hops, vote = await nodes[2].resolve_query("example.com")
    assert (ip, outcome, vote) == ("93.184.216.34", "dht_hit", "3/3"), (ip, outcome, vote)

    # (2) same origin again -> cache_hit, zero hops
    ip, ttl, outcome, hops, vote = await nodes[2].resolve_query("example.com")
    assert (outcome, hops, vote) == ("cache_hit", 0, "cache")

    # (3) DHT majority vote survives one corrupted replica
    cid = chunk_id("example.com")
    replicas, _ = await nodes[0].replica_set(cid)
    by_id = {nd.node_id: nd for nd in nodes}
    by_id[replicas[0]].store[cid] = "6.6.6.6|120"
    ip, _, outcome, _, vote = await nodes[3].resolve_query("example.com")
    assert (ip, outcome, vote) == ("93.184.216.34", "dht_hit", "2/3"), (ip, outcome, vote)

    # (4) unknown name -> fallback / nxdomain
    ip, _, outcome, _, vote = await nodes[1].resolve_query("does-not-exist.test")
    assert ip is None and outcome == "fallback" and vote == "nxdomain"

    # (5) queries.csv exists with the required header and >= our rows
    with open(QUERIES_PATH) as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["timestamp", "domain", "hops", "outcome", "vote_result"]
    outcomes = {r[3] for r in rows[1:]}
    assert {"cache_hit", "dht_hit", "fallback"}.issubset(outcomes), outcomes

    for nd in nodes:
        nd.stop()
    print(f"test_query: PASS  (fallback->writeback->dht_hit->cache_hit, majority vote 2/3, "
          f"{len(rows) - 1} rows logged to queries.csv)")


def test_query():
    asyncio.run(_run())


if __name__ == "__main__":
    test_query()
