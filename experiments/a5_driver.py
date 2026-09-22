#!/usr/bin/env python3
"""Issue #36 [A5] — drive real ledger updates against a LIVE resolver ring and measure them.

This is the write-path counterpart to ``testbed/query_gen.py``: it runs inside a throwaway
container on the ring's Docker network (like query_gen) and, acting as a bare RPC *client*
(a ``SocketNetwork`` used outbound-only, never a ring member), issues N ``admin_propose`` RPCs
to one node — the proposer — which runs ``node/ledger.py::propose_update`` unchanged (Algorithm 3
two-phase commit) and reports back the measured cost. There is no DNS UPDATE opcode and no write
to any frozen protocol code: the ``admin_propose`` / ``admin_ledger_len`` RPCs are inert
diagnostics registered by ``node/run_ring_node.py`` (the ``debug_state`` pattern), and the wire
message count is gathered by ``socket_net.rpc_counter`` around the unchanged commit path.

Per update it logs one CSV row (``--output``):

    seq,domain,outcome,latency_ms,round_trips,messages,entries_appended,ledger_len_cum

  * latency_ms       — wall-clock commit latency measured on the proposer (perf_counter)
  * round_trips      — WIRE RPCs the commit issued (find_successor hops + get_succ_list +
                       ledger_precommit x s + ledger_commit x s); a round-trip = 2 messages
  * messages         — 2 * round_trips (matches sim/ledger_sim's accounting)
  * entries_appended — s if committed else 0 (each committed update appends one hash-chain entry
                       on each of the s replicas); the AUTHORITATIVE ring-wide growth is the
                       before/after ``admin_ledger_len`` total written to ``growth.json``
  * ledger_len_cum   — running sum of entries_appended (the measured growth curve)

Also writes ``<output-dir>/growth.json`` = the ring-wide committed-ledger total before and after
the run (summed over all N nodes), so ledger growth is validated end-to-end (delta == committed*s).

Addressing is deterministic (CLAUDE.md fixed-seed rule): node j has pk ``_pk_for(j)`` and lives at
``<ring-ip-prefix>.<ring-ip-base + j>:<ring-port>`` (the static IPs gen_nodes_compose assigns), so
the whole id->address roster derives from N alone. IPs are passed as literals, so socket_net's
``_resolve`` skips Docker DNS entirely.

Run (inside the ring network, repo mounted at /repo):
    python experiments/a5_driver.py --ring-nodes 32 --updates 50 \
        --ring-ip-prefix 172.30.0 --ring-ip-base 10 --ring-port 7000 \
        --manifest /repo/testbed/dns/zones/MANIFEST.json --output /out/updates.csv
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import random
import sys
from pathlib import Path

# repo root on sys.path so node.* imports work whether run from /repo or the repo root.
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from node.ids import node_id_from_pk          # noqa: E402
from node.query import _encode                # noqa: E402  ("ip|ttl")
from node.run_node import _pk_for             # noqa: E402  (deterministic identity)
from node.socket_net import SocketNetwork     # noqa: E402

DEFAULT_SEED = 20260919
CLIENT_ID = node_id_from_pk(b"a5-driver-client")   # a non-member id, distinct from every node


def _new_ip(i: int) -> str:
    """Fresh answer IP per update (mirrors node/integration_test._new_ip)."""
    return f"198.51.100.{i % 254 + 1}"


def load_domains(manifest: Path, count: int, seed: int) -> list[str]:
    """Pick ``count`` distinct served domains, deterministically (seeded shuffle of the served
    set), so each update targets a different chunk / replica set and the run is reproducible."""
    recs = json.loads(manifest.read_text())["records"]
    doms = sorted(recs.keys())                       # stable base order (independent of dict order)
    random.Random(seed).shuffle(doms)
    if count > len(doms):
        raise SystemExit(f"asked for {count} domains but only {len(doms)} served")
    return doms[:count]


def build_roster(n: int, prefix: str, base: int, port: int) -> dict[int, tuple[str, int]]:
    return {node_id_from_pk(_pk_for(j)): (f"{prefix}.{base + j}", port) for j in range(n)}


async def ring_ledger_total(net: SocketNetwork, roster: dict, timeout: float) -> int:
    """Sum len(node.ledger) over every reachable node (ring-wide committed entries)."""
    total = 0
    for nid in roster:
        try:
            total += int(await net.rpc(CLIENT_ID, nid, "admin_ledger_len", timeout=timeout))
        except Exception:
            pass                                     # a briefly-unreachable node contributes 0
    return total


async def run(args) -> None:
    roster = build_roster(args.ring_nodes, args.ring_ip_prefix, args.ring_ip_base, args.ring_port)
    proposer_id = node_id_from_pk(_pk_for(args.proposer))
    domains = load_domains(Path(args.manifest), args.updates, args.seed)
    net = SocketNetwork(CLIENT_ID, roster)

    before = await ring_ledger_total(net, roster, args.timeout)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    cum = 0
    committed = 0
    for i, domain in enumerate(domains):
        value = _encode(_new_ip(i), args.ttl)
        try:
            res = await net.rpc(CLIENT_ID, proposer_id, "admin_propose",
                                domain, value, "update", timeout=args.timeout)
            ok = bool(res.get("ok"))
            latency = float(res.get("latency_ms", 0.0))
            rts = int(res.get("round_trips", 0))
            msgs = int(res.get("messages", 2 * rts))
        except Exception as e:                       # proposer unreachable / timed out
            ok, latency, rts, msgs = False, args.timeout * 1000.0, 0, 0
            print(f"  update {i} ({domain}) FAILED: {e!r}", flush=True)
        entries = args.replication if ok else 0
        cum += entries
        committed += 1 if ok else 0
        rows.append([i, domain, "committed" if ok else "failed",
                     f"{latency:.4f}", rts, msgs, entries, cum])
        if args.interval_ms > 0:
            await asyncio.sleep(args.interval_ms / 1000.0)

    after = await ring_ledger_total(net, roster, args.timeout)

    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["seq", "domain", "outcome", "latency_ms", "round_trips",
                    "messages", "entries_appended", "ledger_len_cum"])
        w.writerows(rows)

    growth = {"ring_ledger_before": before, "ring_ledger_after": after,
              "ring_ledger_delta": after - before, "committed": committed,
              "updates": args.updates, "replication": args.replication,
              "expected_delta": committed * args.replication}
    (out.parent / "growth.json").write_text(json.dumps(growth, indent=2))

    print(f"[a5] {committed}/{args.updates} committed; ring-wide ledger {before} -> {after} "
          f"(delta {after - before}, expected {growth['expected_delta']}) -> {out}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Drive N ledger updates against a live resolver ring.")
    ap.add_argument("--ring-nodes", type=int, required=True, help="ring size N")
    ap.add_argument("--updates", type=int, default=50, help="number of updates to commit")
    ap.add_argument("--proposer", type=int, default=0, help="node index that proposes (default 0)")
    ap.add_argument("--replication", type=int, default=3, help="replication factor s (frozen 3)")
    ap.add_argument("--ring-ip-prefix", default="172.30.0", help="static IP /24 prefix")
    ap.add_argument("--ring-ip-base", type=int, default=10, help="node 0's last octet")
    ap.add_argument("--ring-port", type=int, default=7000, help="TCP RPC port")
    ap.add_argument("--manifest", default=str(_REPO_ROOT / "testbed/dns/zones/MANIFEST.json"))
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--ttl", type=int, default=300, help="TTL written into each record")
    ap.add_argument("--interval-ms", type=float, default=200.0, help="spacing between updates")
    ap.add_argument("--timeout", type=float, default=15.0, help="per-RPC timeout seconds")
    ap.add_argument("--output", default="/out/updates.csv")
    asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    main()
