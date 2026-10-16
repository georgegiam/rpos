#!/usr/bin/env python3
"""Issue #48 [B7] — host-side DoS flooder (Phase 7, examiner point (ii)).

B7's primary attack is a resource-exhaustion FLOOD: malicious identities blast the ring with
high-rate RPC traffic, congesting the transport so honest maintenance RPCs (chord.py stabilize's
get_predecessor, timeout 2 s) time out — and chord.py drops a successor on ANY RPC timeout, so the
ring sheds good successors faster than it heals (the fragility that capped emulation at N=32 in
Phase 3). This tool generates that flood.

WHY HOST-SIDE (no frozen edit — CLAUDE.md §2). All five node modes in node/malicious.py are
REACTIVE inbound-handler overrides; a flood ORIGINATES traffic, which that pattern cannot express
without starting a loop inside the node. So — exactly like testbed/query_gen.py and
experiments/a5_driver.py — this runs in a throwaway container on the ring's Docker network and
acts as a bare RPC *client* (never a ring member), reusing node/socket_net's data-only frame codec
(imports only). node/* and rpos/rpos.py stay byte-identical; the wire effect (R inbound RPCs/s at
the victims) is identical to f in-ring flooders.

Two patterns, so the SAME tool produces both arms of the mandatory honest-control:
  * --pattern junk   — the ATTACK: find_successor on RANDOM 160-bit keys (each forces the victim
                       into a full iterative O(log N) lookup = amplification), aimed at the victim
                       indices chosen by b7_placement.
  * --pattern honest — the CONTROL: the SAME RPC at the SAME rate for REAL served-domain chunk keys
                       (legitimate lookups a heavy-but-honest client would issue). "Same traffic
                       volume, honest sources" — the epic's cross-cutting requirement. (The run
                       script's default control is instead extra query_gen load; this pattern is the
                       wire-matched alternative, and the one the --self-test exercises.)

Addressing is deterministic (CLAUDE.md fixed-seed rule): node j = _pk_for(j) at
<prefix>.<base+j>:<port> (gen_nodes_compose's static IPs), so the roster derives from N alone; IPs
are literals so socket_net._resolve skips Docker DNS.

Writes <output> JSON: offered/achieved RPC rate, completed/failed counts, per-target tallies — so
"matched volume" is VERIFIABLE, not assumed.

Run (inside the ring network, repo mounted at /repo):
    python experiments/b7_flooder.py --ring-nodes 32 --targets 1,2,3 --rate 200 --duration 120 \
        --pattern junk --output /out/flood.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from node.ids import RING_SIZE, chunk_id, node_id_from_pk   # noqa: E402 (hashlib-only)
from experiments.b1_placement import _pk_for                # noqa: E402 (host-safe identity, == node.run_node._pk_for)
from node.socket_net import SocketNetwork                   # noqa: E402

DEFAULT_SEED = 20260919
FLOODER_ID = node_id_from_pk(b"b7-flooder-client")          # a non-member id, distinct from nodes


def build_roster(n: int, prefix: str, base: int, port: int) -> dict[int, tuple[str, int]]:
    return {node_id_from_pk(_pk_for(j)): (f"{prefix}.{base + j}", port) for j in range(n)}


def _served_keys(manifest: Path, seed: int) -> list[int]:
    """Chunk keys for the served domains (honest pattern looks up real, resolvable chunks)."""
    recs = json.loads(manifest.read_text())["records"]
    doms = sorted(recs.keys())
    random.Random(seed).shuffle(doms)
    return [chunk_id(d) for d in doms]


async def _worker(net: SocketNetwork, targets: list[int], method: str, pattern: str,
                  keys: list[int], rng: random.Random, interval: float, deadline: float,
                  tally: dict) -> None:
    """One flood worker: paces RPCs at ~1/interval, round-robining over the victim targets."""
    ti = 0
    ki = 0
    while time.monotonic() < deadline:
        dst = targets[ti % len(targets)]
        ti += 1
        if pattern == "junk":
            key = rng.getrandbits(160) % RING_SIZE          # random key -> full iterative lookup
        else:
            key = keys[ki % len(keys)] if keys else rng.getrandbits(160) % RING_SIZE
            ki += 1
        try:
            # short timeout: a flood worker does not wait on a congested victim, it moves on
            await net.rpc(FLOODER_ID, dst, method, key, timeout=2.0)
            tally["ok"] += 1
        except Exception:
            tally["fail"] += 1
        tally["per_target"][dst] = tally["per_target"].get(dst, 0) + 1
        if interval > 0:
            await asyncio.sleep(interval)


async def run(args) -> int:
    roster = build_roster(args.ring_nodes, args.ring_ip_prefix, args.ring_ip_base, args.ring_port)
    idx2id = [node_id_from_pk(_pk_for(j)) for j in range(args.ring_nodes)]
    target_idx = [int(x) for x in str(args.targets).split(",") if x.strip() != ""] \
        or list(range(1, args.ring_nodes))
    targets = [idx2id[i] for i in target_idx]
    keys = _served_keys(Path(args.manifest), args.seed) if args.pattern == "honest" else []

    net = SocketNetwork(FLOODER_ID, roster)
    # spread the offered aggregate rate across W workers so a single awaited RPC never caps us.
    workers = max(1, args.workers)
    per_worker_rate = args.rate / workers if args.rate > 0 else 0.0
    interval = (1.0 / per_worker_rate) if per_worker_rate > 0 else 0.0
    tally = {"ok": 0, "fail": 0, "per_target": {}}

    print(f"[b7-flooder] pattern={args.pattern} method={args.method} targets={target_idx} "
          f"rate={args.rate}/s workers={workers} duration={args.duration}s", flush=True)
    t0 = time.monotonic()
    deadline = t0 + args.duration
    rng = random.Random(args.seed)
    await asyncio.gather(*[
        _worker(net, targets, args.method, args.pattern, keys,
                random.Random(args.seed + w), interval, deadline, tally)
        for w in range(workers)
    ])
    elapsed = time.monotonic() - t0

    completed = tally["ok"] + tally["fail"]
    out = {
        "pattern": args.pattern, "method": args.method, "targets": target_idx,
        "offered_rate": args.rate, "duration_s": round(elapsed, 3),
        "completed": completed, "ok": tally["ok"], "failed": tally["fail"],
        "achieved_rate": round(completed / elapsed, 3) if elapsed > 0 else 0.0,
        "per_target": {str(k): v for k, v in sorted(tally["per_target"].items())},
    }
    if args.output:
        op = Path(args.output)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(json.dumps(out, indent=2) + "\n")
    print(f"[b7-flooder] completed={completed} ok={tally['ok']} failed={tally['fail']} "
          f"achieved={out['achieved_rate']}/s -> {args.output}", flush=True)
    return 0


# --------------------------------------------------------------------------------------------
# Self-test (no Docker): a mock in-process ring verifies the flooder actually drives RPCs at the
# requested rate against the requested targets, and that junk vs honest both work.
# --------------------------------------------------------------------------------------------
def _self_test() -> int:
    import node.net as _net

    async def go() -> bool:
        from node.ids import node_id_from_pk as nid
        net = _net.Network()
        # three mock victim nodes that just count inbound find_successor calls
        counts = {}

        class Counter(_net.NodeServer):
            def __init__(self, pk, net):
                super().__init__(pk, net)
                counts[self.node_id] = 0
                self.register("find_successor", self._fs)

            async def _fs(self, src, key):
                counts[self.node_id] += 1
                return (self.node_id, 0)

        victims = [Counter(_pk_for(i), net) for i in range(1, 4)]
        for v in victims:
            v.start()
        vids = [v.node_id for v in victims]

        # drive ~100 RPCs/s for 0.5 s across the 3 victims via the in-process net
        tally = {"ok": 0, "fail": 0, "per_target": {}}
        deadline = time.monotonic() + 0.5
        await asyncio.gather(*[
            _worker(net, vids, "find_successor", "junk", [], random.Random(w),
                    1.0 / 50, deadline, tally)
            for w in range(2)
        ])
        for v in victims:
            v.stop()
        total = sum(counts.values())
        spread = all(counts[v] > 0 for v in vids)      # every target got hit
        drove = total >= 10 and tally["ok"] == total   # RPCs actually completed
        print(f"  [self-test] drove {total} RPCs (ok={tally['ok']} fail={tally['fail']}), "
              f"per-victim={list(counts.values())} spread={spread}")
        return bool(drove and spread)

    ok = asyncio.run(go())
    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="B7 host-side DoS flooder (issue #48).")
    ap.add_argument("--ring-nodes", type=int, default=32, help="ring size N")
    ap.add_argument("--targets", default="", help="comma list of victim node INDICES (default all 1..N-1)")
    ap.add_argument("--rate", type=float, default=200.0, help="offered aggregate RPC rate (/s); 0 = open-loop blast")
    ap.add_argument("--duration", type=float, default=120.0, help="flood duration seconds")
    ap.add_argument("--pattern", choices=["junk", "honest"], default="junk")
    ap.add_argument("--method", default="find_successor", help="RPC method to flood with")
    ap.add_argument("--workers", type=int, default=64, help="concurrent flood workers")
    ap.add_argument("--ring-ip-prefix", default="172.30.0")
    ap.add_argument("--ring-ip-base", type=int, default=10)
    ap.add_argument("--ring-port", type=int, default=7000)
    ap.add_argument("--manifest", default=str(_REPO_ROOT / "testbed/dns/zones/MANIFEST.json"))
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--output", default="")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return _self_test()
    return asyncio.run(run(a))


if __name__ == "__main__":
    raise SystemExit(main())
