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

from node.ids import RING_BITS, RING_SIZE, node_id_from_pk
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
        join_stagger=float(os.environ.get("JOIN_STAGGER", "0.4")),
    )


def _build_roster(c) -> dict[int, tuple[str, int]]:
    """id -> (host, port) for every node, derived deterministically from N.

    If the compose passed static container IPs (RING_IP_PREFIX/RING_IP_BASE — node j lives at
    ``<prefix>.<base+j>``), address peers by IP so the hot path NEVER touches Docker's embedded
    DNS. Per-connect hostname resolution was the dominant N=64 failure: under the startup
    connection storm the embedded DNS stalls ~2 s or fails ~1-3% of lookups, which fails
    maintenance RPCs and churns Chord successors (connect-by-IP measured 0% failures / 0.2 ms).
    Falls back to Docker service names when no static-IP scheme is provided (e.g. unit tests)."""
    prefix = os.environ.get("RING_IP_PREFIX")
    base = os.environ.get("RING_IP_BASE")
    if prefix and base:
        b = int(base)
        return {node_id_from_pk(_pk_for(j)): (f"{prefix}.{b + j}", c["ring_port"])
                for j in range(c["n"])}
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


async def _refresh_top_fingers(node, k: int) -> None:
    """Refresh the top ``k`` (highest-index) finger slots this round, concurrently.

    Why this exists (Phase 3 scale fix, chord.py left byte-identical): chord.py's ``fix_fingers``
    cycles ONE of the M=160 slots per call. At N=64 the 63 non-seed nodes all join the seed at
    once (docker compose up -d), forming a star that ``stabilize`` untangles into a ring; a finger
    that ``fix_fingers`` set during that unstable phase points at the wrong node and is not
    revisited for a full ~160-round cycle, so lookups fall back to O(N) successor walks (measured:
    median ~30 hops) long after the ring is cycle-consistent, blowing past the 5 s query timeout.

    Only the HIGH fingers matter: with N nodes uniformly in the 2**160 ring the mean gap is
    2**160/N, so a finger whose jump 2**i is smaller than that gap just points at the immediate
    successor (harmless, and ``closest_preceding`` skips such duplicates). So we refresh only the
    top ``k`` slots — enough to cover the ~log2(N) useful ones with margin — instead of all 160.
    Refreshing all 160 (an earlier attempt) spawned 160 concurrent lookups per node per round and
    periodically saturated event loops, starving the stabilize/notify RPCs and ORPHANING nodes;
    a small ``k`` avoids that while keeping the useful fingers fresh within one round of the ring
    stabilising (measured drop to ~3 hops). Same rule as fix_fingers (successor of node_id+2**i),
    run concurrently; drives only chord.py's public find_successor and writes its ``fingers`` list
    — the Chord algorithm is unchanged.
    """
    lo = max(0, RING_BITS - k)
    idxs = list(range(lo, RING_BITS))
    starts = [(node.node_id + (1 << i)) % RING_SIZE for i in idxs]
    results = await asyncio.gather(*(node.find_successor(s) for s in starts),
                                   return_exceptions=True)
    for i, r in zip(idxs, results):
        if not isinstance(r, BaseException):
            node.fingers[i] = r[0]


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

    # read-only introspection RPC (diagnostics only: verify finger convergence at scale).
    async def _h_debug_state(src):
        return {"node_id": node.node_id, "pred": node.predecessor,
                "succ_list": list(node.successor_list), "fingers": list(node.fingers)}
    node.register("debug_state", _h_debug_state)

    # 1) serve RPCs BEFORE joining, so our successor can challenge us during admission.
    await net.start_server("0.0.0.0", c["ring_port"])

    # pre-resolve peer IPs in the background so the hot path never hits Docker's (load-flaky)
    # embedded DNS — the real cause of the N=64 convergence churn (see socket_net._ip_cache).
    asyncio.ensure_future(net.prewarm())

    # 2) DNS front end.
    loop = asyncio.get_event_loop()
    await loop.create_datagram_endpoint(lambda: _DnsProto(node),
                                        local_addr=("0.0.0.0", c["dns_port"]))

    zone_n = len(upstream.zone) if upstream else 0
    print(f"[ring {self_id:#x}] index={c['index']} N={c['n']} mode={c['mode']} "
          f"ring_port={c['ring_port']} dns_port={c['dns_port']} zone={zone_n} "
          f"(seed={c['seed_index']})", flush=True)

    # 3) create (seed) or join (everyone else).
    #
    # STAGGERED joins: if all N nodes join the seed at once (docker compose up -d), they form a
    # giant star that stabilize must untangle over ~O(N) rounds, and the find_successor traffic
    # during that long unstable window churns successors faster than they heal — at N=64 the
    # cycle then never fully converges. Waiting index*JOIN_STAGGER before joining grows the ring
    # incrementally, so each node joins a nearly-stable ring and converges almost immediately.
    seed_id = node_id_from_pk(_pk_for(c["seed_index"]))
    if c["index"] == c["seed_index"]:
        await node.create()
        print(f"[ring {self_id:#x}] created ring as seed", flush=True)
    else:
        await asyncio.sleep(c["index"] * c["join_stagger"])
        await _join_with_retry(node, seed_id, c)

    # 4) maintenance loop: the socket equivalent of the Phase 2 round-drivers.
    #
    # PRIORITY: keep the ring CYCLE converging. chord.py's stabilize drops its successor on ANY
    # RPC exception (including a transient timeout), so if heavy maintenance floods the transport
    # and makes stabilize's get_predecessor time out, nodes shed good successors faster than they
    # heal and the cycle never converges (measured: only ~33/64 correct successors under a
    # per-round finger storm). So stabilize/check_predecessor run every round on their own, and
    # the heavier finger refresh runs only OCCASIONALLY, well spaced from the challenge round, so
    # it never competes with stabilize in the same tick.
    challenge_every = max(1, int(5.0 / c["maint_interval"]))   # ~ every 5s
    fingers_every = max(1, int(4.0 / c["maint_interval"]))     # top-finger refresh ~ every 4s
    top_k = min(RING_BITS, max(16, 2 * max(1, c["n"]).bit_length() + 6))
    # Priority order per round: stabilize + check_predecessor (the cheap ring-cycle protocol)
    # always run; the heavier find_successor-based maintenance (top-finger refresh, PoSpace
    # challenge) is spaced out so it competes less with stabilize. NOTE (flagged, not hidden):
    # at N=64 in the 64-container testbed this still does not fully converge the cycle under load
    # — see CLAUDE.md Phase 3 "N=64 convergence" for the measured behaviour and root cause.
    round_no = 0
    while True:
        round_no += 1
        try:
            await node.stabilize()
            await node.check_predecessor()
            if round_no % fingers_every == 0 and round_no % challenge_every != 0:
                await _refresh_top_fingers(node, top_k)
            else:
                await node.fix_fingers()
            if round_no % challenge_every == 0:
                await node.challenge_round()
                await node.refresh_expired()
        except Exception as e:
            print(f"[ring {self_id:#x}] maintenance error: {e!r}", flush=True)
        await asyncio.sleep(c["maint_interval"])


if __name__ == "__main__":
    asyncio.run(_main())
