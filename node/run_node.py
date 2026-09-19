"""Issue #19 [P3-2] — scaffold entrypoint to bring ONE resolver node up in a container.

HONEST SCAFFOLD. This constructs a real resolver node, builds a real v3 DRG PoSpace plot
(so the container genuinely exercises the phase1 plot/commit path), and then stays alive.
It does **not** join a Chord ring and it does **not** answer DNS across containers, because
``node/net.py`` is an in-process asyncio message bus only — there is no cross-container
transport yet. Real inter-node RPC (host:port addressing, wire serialization of RPC args
incl. PoSpace proofs, a background stabilize/challenge loop) and DNS-over-UDP binding are a
separate, deferred issue. See testbed/README.md.

The only socket this opens is a bare TCP liveness port (9910) so Docker's healthcheck can
confirm the container is up; it is NOT a Chord or DNS port and speaks no protocol beyond
echoing the node id.

Config comes from environment variables (all optional; defaults match the Phase 2 test
scale):

    NODE_INDEX         integer id seed (default 0); under ``docker compose --scale`` the
                       trailing replica number in the container hostname overrides it so each
                       replica gets a distinct, reproducible identity
    PLOT_N             DRG plot size in leaves (default 1024, the Phase 2 test scale)
    DRG_INDEGREE       DRG in-degree delta (default 2)
    CHALLENGE_TIMEOUT  PoSpace challenge timeout in seconds (default 2.0)
    SEED               per-node RNG seed (default 20260919)
    MALICIOUS_MODE     honest | lie | drop | misroute | forge (default honest)

Run: ``python -m node.run_node`` (the container CMD).
"""
import asyncio
import hashlib
import os
import socket

from node.malicious import MODES, MaliciousNode
from node.net import Network
from node.pospace_admission import PoSpaceNode

LIVENESS_PORT = 9910
HEARTBEAT_SECONDS = 30


def _pk_for(index: int) -> bytes:
    """Deterministic 33-byte public key for node ``index``.

    Mirrors node/tests/util.pk_for so identities are reproducible (CLAUDE.md fixed-seed
    rule), but is defined here rather than imported so a runtime entrypoint does not depend
    on the test package.
    """
    return b"node-pk-" + index.to_bytes(4, "big") + b"\x00" * 21


def _node_index() -> int:
    """A distinct node index for this container.

    If ``NODE_INDEX`` is set (single-node runs / tests) it wins and gives a reproducible id.
    Otherwise — the ``docker compose --scale`` case — there is no stable per-replica ordinal
    and the default container hostname is the (unique) container id, so we hash it into a
    32-bit index. That guarantees a distinct, valid identity per container but is NOT stable
    across runs; the deferred transport issue should assign identity explicitly.
    """
    env = os.environ.get("NODE_INDEX")
    if env:
        return int(env)
    digest = hashlib.sha256(socket.gethostname().encode()).digest()
    return int.from_bytes(digest[:4], "big")


def _config() -> dict:
    mode = os.environ.get("MALICIOUS_MODE", "honest")
    if mode not in MODES:
        raise ValueError(f"MALICIOUS_MODE must be one of {MODES}, got {mode!r}")
    return {
        "index": _node_index(),
        "plot_n": int(os.environ.get("PLOT_N", "1024")),
        "drg_indegree": int(os.environ.get("DRG_INDEGREE", "2")),
        "challenge_timeout": float(os.environ.get("CHALLENGE_TIMEOUT", "2.0")),
        "seed": int(os.environ.get("SEED", "20260919")),
        "mode": mode,
    }


async def _main() -> None:
    c = _config()
    net = Network()  # private, in-process; no peers by design (scaffold — see module docstring)
    pk = _pk_for(c["index"])
    kw = dict(plot_n=c["plot_n"], drg_indegree=c["drg_indegree"],
              challenge_timeout=c["challenge_timeout"], seed=c["seed"])
    node = (PoSpaceNode(pk, net, **kw) if c["mode"] == "honest"
            else MaliciousNode(pk, net, malicious_mode=c["mode"], **kw))

    # Build the real v3 DRG plot + Merkle commitment (NOT create(): create() would start the
    # serve loop and log a genesis join, falsely implying ring membership the scaffold lacks).
    node._build_plot()
    print(f"[node {node.node_id:#x}] plot built "
          f"(N={c['plot_n']}, delta={c['drg_indegree']}, mode={c['mode']}); "
          f"scaffold idle — no ring (cross-container transport is a deferred issue)",
          flush=True)

    async def _liveness(_reader, writer):
        writer.write(f"{node.node_id:#x}\n".encode())
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(_liveness, "0.0.0.0", LIVENESS_PORT)
    async with server:
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            print(f"[node {node.node_id:#x}] alive (plot_root={node.plot_root.hex()[:12]})",
                  flush=True)


if __name__ == "__main__":
    asyncio.run(_main())
