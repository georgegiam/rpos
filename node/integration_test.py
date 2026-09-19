"""Phase 2 integration test (issue #16) — the full resolver node, end to end.

Every Phase 2 sub-issue (#9 Chord, #10 storage, #11 DNS, #12 query, #13 ledger, #14 PoSpace
admission) has its own unit test; this one exercises all of them together on a single 5-node
ring, driving the honest happy path:

    join (admission-gated)  ->  store 20 domains  ->  resolve each via DNS
                            ->  commit 5 ledger updates  ->  challenge every node's PoSpace

`PoSpaceNode` sits at the bottom of the mixin chain (Chord + storage + DNS + query + ledger +
PoSpace admission), so no new node code is needed — this is orchestration over existing public
methods. In-process asyncio transport only (Phase 3 swaps in sockets). Self-running, no pytest:
`python -m node.integration_test`. One summary row per stage lands in
`node/results/integration_test.csv`; the component layers also append to their own CSVs.

Malicious behaviours (#15) are out of scope here — adversarial end-to-end runs are Phase 7.
"""
import asyncio
import os

import dns.rcode

from node.dns_interface import make_a_query, parse_a_response
from node.ids import chunk_id
from node.logs import RESULTS_DIR, append_row, now_iso
from node.net import Network
from node.pospace_admission import PoSpaceNode
from node.query import IterativeResolver, _encode
from node.tests.util import build_ring, ring_is_consistent

RESULTS_CSV = "integration_test.csv"
RESULTS_HEADER = ["timestamp", "stage", "detail", "result"]
RESULTS_PATH = os.path.join(RESULTS_DIR, RESULTS_CSV)

N_NODES = 5
N_DOMAINS = 20
N_UPDATES = 5
TTL = 120


def _domain(i: int) -> str:
    return f"example{i}.com"


def _ip(i: int) -> str:
    return f"93.184.216.{i}"


def _new_ip(i: int) -> str:
    return f"198.51.100.{i}"


async def _run() -> None:
    # Fresh summary artifact so a run is self-contained (matches the other Phase 2 tests).
    if os.path.exists(RESULTS_PATH):
        os.remove(RESULTS_PATH)

    def record(stage: str, detail: str, ok: bool) -> None:
        append_row(RESULTS_CSV, RESULTS_HEADER,
                   [now_iso(), stage, detail, "pass" if ok else "fail"])
        assert ok, f"{stage}: {detail}"

    zone = {_domain(i): _ip(i) for i in range(N_DOMAINS)}
    upstream = IterativeResolver(zone, ttl=TTL)
    nodes: list[PoSpaceNode] = []
    net = Network()
    try:
        # --- Stage 0: 5 nodes join a ring (each join is admission-gated) ---
        nodes = await build_ring(PoSpaceNode, net, n=N_NODES, upstream=upstream)
        ring_ok = (all(net.is_up(nd.node_id) for nd in nodes)
                   and ring_is_consistent(nodes))
        record("ring_join", f"{N_NODES}/{N_NODES} admitted, ring consistent", ring_ok)

        # --- Stage 1: store 20 domains (resolve -> fallback -> store to s replicas) ---
        stored = 0
        for i in range(N_DOMAINS):
            origin = nodes[i % N_NODES]
            ip, _ttl, outcome, _hops, vote = await origin.resolve_query(_domain(i))
            if ip == _ip(i) and outcome == "fallback" and vote.startswith("stored:"):
                stored += 1
        record("store", f"{stored}/{N_DOMAINS} stored", stored == N_DOMAINS)

        # --- Stage 2: resolve each via DNS (wire format) from a non-storing node -> DHT hit ---
        resolved = 0
        for i in range(N_DOMAINS):
            resolver = nodes[(i + 1) % N_NODES]          # not the node that stored domain i
            wire = await resolver.handle_dns_query(make_a_query(_domain(i)))
            rcode, ips = parse_a_response(wire)
            if rcode == dns.rcode.NOERROR and ips == [_ip(i)]:
                resolved += 1
        record("resolve_dns", f"{resolved}/{N_DOMAINS} NOERROR", resolved == N_DOMAINS)

        # --- Stage 3: commit 5 ledger updates (Algorithm 3), then verify the chain ---
        committed = 0
        for i in range(N_UPDATES):
            origin = nodes[i % N_NODES]
            domain, value = _domain(i), _encode(_new_ip(i), TTL)
            ok = await origin.propose_update(domain, value)
            primary_id, _ = await origin.find_successor(chunk_id(domain))
            primary = next(nd for nd in nodes if nd.node_id == primary_id)
            last = primary.ledger[-1] if primary.ledger else {}
            if (ok and primary.verify_chain()
                    and last.get("value") == value and last.get("action") == "update"):
                committed += 1
        record("ledger_commit", f"{committed}/{N_UPDATES} committed", committed == N_UPDATES)

        # --- Stage 4: challenge every node's PoSpace — all pass ---
        passed = 0
        for i, target in enumerate(nodes):
            challenger = nodes[(i + 1) % N_NODES]        # a peer other than the target
            if await challenger.challenge_peer(target.node_id):
                passed += 1
        challenge_ok = (passed == N_NODES
                        and all(net.is_up(nd.node_id) for nd in nodes)
                        and all(sum(nd.fail_counts.values()) == 0 for nd in nodes))
        record("pospace_challenge", f"{passed}/{N_NODES} pass, none evicted", challenge_ok)

        record("overall", "all stages passed", True)
    finally:
        for nd in nodes:
            nd.stop()


def test_integration() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    test_integration()
    print("integration_test: OK ->", RESULTS_PATH)
