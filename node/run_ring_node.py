"""Container entrypoint for a node that joins a REAL Chord ring over sockets (epic #24).

This is the networked counterpart of the ``node/run_node.py`` scaffold (which stays as the
in-process liveness stub and is left untouched). Here the node:

  1. builds its v3 DRG PoSpace plot,
  2. starts a TCP RPC server (``node/socket_net.SocketNetwork``) so peers can reach it,
  3. binds a UDP DNS server so the query generator can send it real DNS A queries,
  4. creates the ring (seed) or joins it via the seed (everyone else), gated on a PoSpace
     admission challenge exactly as in Phase 2, and
  5. runs a background maintenance loop (stabilize / fix_fingers / periodic PoSpace challenge /
     TTL refresh), the socket equivalent of the round-drivers used in the Phase 2 tests.

Every Chord RPC (find_successor, notify, get_predecessor, get_succ_list, get/put_chunk,
ledger 2PC, pospace_commitment/challenge) now travels over the network between containers.
The query path, majority vote, ledger and PoSpace verify are the SAME code as in-process —
only the transport differs — so nodes-mode results are comparable to the Phase 2 tests.

Identity + addressing are deterministic (CLAUDE.md fixed-seed rule): node j has pk
``_pk_for(j)`` (reused from run_node.py) and lives at ``<NODE_NAME_PREFIX><j>:<RING_PORT>``,
so every node derives the full id->address roster from N alone — no registry needed. The
roster is address resolution only; the ring itself (successors/predecessor/fingers) is
discovered dynamically over the sockets.

Config (environment):
    NODE_INDEX        this node's index 0..N-1                  (required)
    NODES             ring size N                               (required)
    SEED_INDEX        index of the bootstrap/seed node          [0]
    NODE_NAME_PREFIX  peer hostname prefix (Docker service/ctr) [rpos-node-]
    RING_PORT         TCP port for Chord RPCs                   [7000]
    DNS_PORT          UDP port for the DNS interface            [5300]
    ZONE_JSON         path to a DNS MANIFEST.json for fallback  [/zones/MANIFEST.json]
    PLOT_N            DRG plot leaves                           [1024]
    DRG_INDEGREE      DRG in-degree delta                       [2]
    CHALLENGE_TIMEOUT PoSpace response timeout seconds          [2.0]
    SEED              per-node RNG seed                         [20260919]
    MALICIOUS_MODE    honest|lie|drop|misroute|forge            [honest]
    MAINT_INTERVAL    maintenance-loop period seconds           [1.0]
    JOIN_TIMEOUT      seconds to keep retrying the join         [120]

Run: ``python -m node.run_ring_node``.
"""
import asyncio
import json
import os

from node.ids import node_id_from_pk
from node.malicious import MODES, MaliciousNode
from node.pospace_admission import AdmissionError, PoSpaceNode
from node.query import IterativeResolver
from node.run_node import _pk_for
from node.socket_net import SocketNetwork


def _cfg():
    mode = os.environ.get("MALICIOUS_MODE", "honest")
    if mode not in MODES:
        raise ValueError(f"MALICIOUS_MODE must be one of {MODES}, got {mode!r}")
    return dict(
        index=int(os.environ["NODE_INDEX"]),
        n=int(os.environ["NODES"]),
        seed_index=int(os.environ.get("SEED_INDEX", "0")),
        prefix=os.environ.get("NODE_NAME_PREFIX", "rpos-node-"),
        ring_port=int(os.environ.get("RING_PORT", "7000")),
        dns_port=int(os.environ.get("DNS_PORT", "5300")),
        zone_json=os.environ.get("ZONE_JSON", "/zones/MANIFEST.json"),
        plot_n=int(os.environ.get("PLOT_N", "1024")),
        drg_indegree=int(os.environ.get("DRG_INDEGREE", "2")),
        challenge_timeout=float(os.environ.get("CHALLENGE_TIMEOUT", "2.0")),
        seed=int(os.environ.get("SEED", "20260919")),
        mode=mode,
        maint_interval=float(os.environ.get("MAINT_INTERVAL", "1.0")),
        join_timeout=float(os.environ.get("JOIN_TIMEOUT", "120")),
    )


def _build_roster(c) -> dict[int, tuple[str, int]]:
    """id -> (host, port) for every node, derived deterministically from N."""
    return {node_id_from_pk(_pk_for(j)): (f"{c['prefix']}{j}", c["ring_port"])
            for j in range(c["n"])}


def _load_upstream(path: str) -> IterativeResolver | None:
    """Build the fallback (iterative) resolver from a DNS MANIFEST.json, so a DHT miss can be
    resolved once and then stored into the ring. Absent file -> no fallback (miss = NXDOMAIN)."""
    try:
        with open(path) as f:
            recs = json.load(f)["records"]
    except Exception:
        return None
    zone = {d: r["answer_ip"] for d, r in recs.items()}
    return IterativeResolver(zone=zone, ttl=300, steps=3)


class _DnsProto(asyncio.DatagramProtocol):
    """UDP DNS front end: hand each datagram to the node's real handler and reply."""

    def __init__(self, node):
        self.node = node
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data, addr):
        try:
            resp = await self.node.handle_dns_query(data)
        except Exception:
            return
        if self.transport is not None:
            self.transport.sendto(resp, addr)


async def _join_with_retry(node, seed_id: int, c) -> None:
    """Keep retrying join() until the seed's ring is reachable and admits us."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + c["join_timeout"]
    attempt = 0
    while True:
        attempt += 1
        try:
            await node.join(seed_id)
            print(f"[ring {node.node_id:#x}] joined via seed {seed_id:#x} "
                  f"(attempt {attempt}); successor={node.successor():#x}", flush=True)
            return
        except (AdmissionError, ConnectionError, OSError, asyncio.TimeoutError) as e:
            if loop.time() >= deadline:
                raise
            await asyncio.sleep(min(2.0, 0.3 * attempt))


async def _main() -> None:
    c = _cfg()
    pk = _pk_for(c["index"])
    self_id = node_id_from_pk(pk)
    roster = _build_roster(c)
    net = SocketNetwork(self_id, roster)
    upstream = _load_upstream(c["zone_json"])

    kw = dict(plot_n=c["plot_n"], drg_indegree=c["drg_indegree"],
              challenge_timeout=c["challenge_timeout"], seed=c["seed"], upstream=upstream)
    node = (PoSpaceNode(pk, net, **kw) if c["mode"] == "honest"
            else MaliciousNode(pk, net, malicious_mode=c["mode"], **kw))

    # 1) serve RPCs BEFORE joining, so our successor can challenge us during admission.
    await net.start_server("0.0.0.0", c["ring_port"])

    # 2) DNS front end.
    loop = asyncio.get_event_loop()
    await loop.create_datagram_endpoint(lambda: _DnsProto(node),
                                        local_addr=("0.0.0.0", c["dns_port"]))

    zone_n = len(upstream.zone) if upstream else 0
    print(f"[ring {self_id:#x}] index={c['index']} N={c['n']} mode={c['mode']} "
          f"ring_port={c['ring_port']} dns_port={c['dns_port']} zone={zone_n} "
          f"(seed={c['seed_index']})", flush=True)

    # 3) create (seed) or join (everyone else).
    seed_id = node_id_from_pk(_pk_for(c["seed_index"]))
    if c["index"] == c["seed_index"]:
        await node.create()
        print(f"[ring {self_id:#x}] created ring as seed", flush=True)
    else:
        await _join_with_retry(node, seed_id, c)

    # 4) maintenance loop: the socket equivalent of the Phase 2 round-drivers.
    challenge_every = max(1, int(5.0 / c["maint_interval"]))   # ~ every 5s
    round_no = 0
    while True:
        round_no += 1
        try:
            await node.stabilize()
            await node.fix_fingers()
            await node.check_predecessor()
            if round_no % challenge_every == 0:
                await node.challenge_round()
                await node.refresh_expired()
        except Exception as e:
            print(f"[ring {self_id:#x}] maintenance error: {e!r}", flush=True)
        await asyncio.sleep(c["maint_interval"])


if __name__ == "__main__":
    asyncio.run(_main())
