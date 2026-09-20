"""Test for epic #24 — real socket transport forms a Chord ring across separate stacks.

This is the Docker-free proof that SocketNetwork is a faithful transport swap: 5 nodes, each
with its OWN SocketNetwork bound to a distinct localhost port, create/join a ring over TCP,
converge under the stabilize protocol, and then answer a real wire-format DNS query end to
end (cache/DHT miss -> fallback -> store -> answer). Cross-node find_successor is checked
against brute-force ground truth, and a stored chunk is read back by majority vote from a
different node — all over sockets. Hop counts are logged to node/results/queries.csv.

If this passes, the only thing Docker adds is separate network namespaces + tc netem; the
protocol logic is identical to the in-process Phase 2 tests.
"""
import asyncio
import random

from node.dns_interface import make_a_query, parse_a_response
from node.ids import RING_SIZE, node_id_from_pk
from node.pospace_admission import PoSpaceNode
from node.query import IterativeResolver
from node.socket_net import SocketNetwork
from node.tests.util import expected_successor, pk_for, ring_is_consistent

BASE_PORT = 7150
N = 5
ZONE = {f"d{i}.example": f"10.9.{i}.1" for i in range(20)}


async def _rounds(nodes, rounds: int) -> None:
    for _ in range(rounds):
        for nd in nodes:
            if nd.alive:
                await nd.stabilize()
        for nd in nodes:
            if nd.alive:
                await nd.fix_fingers()
                await nd.check_predecessor()
        await asyncio.sleep(0)


async def _run() -> None:
    roster = {node_id_from_pk(pk_for(i)): ("127.0.0.1", BASE_PORT + i) for i in range(N)}
    nodes, nets = [], []
    for i in range(N):
        pk = pk_for(i)
        net = SocketNetwork(node_id_from_pk(pk), roster)
        nd = PoSpaceNode(pk, net, plot_n=256, drg_indegree=2, seed=20260919,
                         upstream=IterativeResolver(zone=ZONE))
        nets.append(net)
        nodes.append(nd)

    try:
        # every node must be serving before any admission challenge can call back
        for i, net in enumerate(nets):
            await net.start_server("127.0.0.1", BASE_PORT + i)

        # seed creates; the rest join over sockets, gated on a PoSpace challenge
        await nodes[0].create()
        for nd in nodes[1:]:
            await nd.join(nodes[0].node_id)
            await _rounds(nodes, 6)
        await _rounds(nodes, 40)

        node_ids = [nd.node_id for nd in nodes]

        # (1) the ring converged over sockets
        assert ring_is_consistent(nodes), "socket ring did not converge to a consistent cycle"
        for nd in nodes:
            assert len(nd.successor_list) == 3

        # (2) cross-node find_successor over TCP matches brute-force ground truth
        rng = random.Random(24680)
        for _ in range(60):
            key = rng.randrange(RING_SIZE)
            want = expected_successor(key, node_ids)
            got, hops = await rng.choice(nodes).find_successor(key)
            assert got == want, f"find_successor({key:#x}): got {got:#x} want {want:#x}"
            assert hops >= 0

        # (3) a chunk stored by one node is read back by majority vote from another
        writer, reader = nodes[1], nodes[3]
        written, _ = await writer.store_chunk("d7.example", "10.9.7.1|300")
        assert len(written) == 3, f"expected s=3 replicas written, got {len(written)}"
        value, vote, _ = await reader.get_chunk("d7.example")
        assert value == "10.9.7.1|300", f"majority read wrong value: {value!r} ({vote})"

        # (4) a real wire-format DNS query resolves end to end through a node
        wire = make_a_query("d3.example")
        resp = await nodes[2].handle_dns_query(wire)
        rcode, ips = parse_a_response(resp)
        assert rcode == 0 and ips == ["10.9.3.1"], f"DNS answer wrong: rcode={rcode} ips={ips}"

        # a brand-new domain: DHT miss -> fallback -> stored, so a second query is a DHT hit
        ip1, _t, out1, _h, _v = await nodes[4].resolve_query("d11.example")
        ip2, _t, out2, hops2, _v2 = await nodes[0].resolve_query("d11.example")
        assert ip1 == "10.9.11.1" and out1 == "fallback"
        assert ip2 == "10.9.11.1" and out2 in ("dht_hit", "cache_hit")

        print(f"test_socket_net: PASS  (N={N} over TCP, ring consistent, 60 lookups correct, "
              f"s=3 replicas, DNS resolves, miss->fallback->hit)")
    finally:
        for nd in nodes:
            nd.stop()
        for net in nets:
            await net.stop_server()


def test_socket_net():
    asyncio.run(_run())


if __name__ == "__main__":
    test_socket_net()
