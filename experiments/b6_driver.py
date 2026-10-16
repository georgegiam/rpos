#!/usr/bin/env python3
"""Issue #47 [B6] — OPTIONAL socket cross-check driver for the malicious ledger proposer.

The in-process ring (experiments/b6_proposer.py) is the PRIMARY, authoritative measurement (and the
only one that can exercise eviction — socket _evict is a no-op). This driver is the optional Docker
socket anchor (B4 pattern): it confirms that over the REAL wire, honest replicas commit a FORGED
update exactly as they commit a valid one — i.e. the bad-update rejection rate is 0 % on the live
ring too, not an in-process artifact.

It is a thin variant of experiments/a5_driver.py: a bare RPC client (never a ring member) that calls
the inert ``admin_propose`` RPC (node/run_ring_node.py, from A5, which runs node/ledger.py's
propose_update UNCHANGED). The ONLY difference is the VALUE proposed:

  * --mode forged  : the attacker IP 6.6.6.6 (node/malicious.FORGED_IP) for a REAL served domain —
                     i.e. an INVALID update (wrong answer). Expect: committed (rejection 0).
  * --mode valid   : the domain's correct answer_ip — the HONEST control. Expect: committed.

Equivalence caveat (documented in B6_NOTES.md): admin_propose makes an honest node the puppet
proposer; this faithfully measures "do honest replicas reject a bad value?" because the replica
handlers never check the proposer's identity (node/ledger.py:51-70). The point is the REPLICAS'
(non-)validation, which is identical whoever proposes.

Writes/append one CSV row to --output (default results/B6_proposer_socket.csv):

    source,mode,ring_nodes,proposals,committed,rejected,rejection_rate_pct,ledger_delta,expected_delta,note

ledger_delta = ring-wide committed-ledger growth (sum of admin_ledger_len before/after), which must
equal committed*s — the wire proof that the forged entries were appended to the honest replicas.

No frozen edit (CLAUDE.md §2): imports/reads only; reuses a5_driver's roster/ledger helpers.

Run (inside the ring network, repo mounted at /repo) — see experiments/run_b6.sh:
    python experiments/b6_driver.py --ring-nodes 32 --mode forged --updates 20 \
        --ring-ip-prefix 172.30.0 --ring-ip-base 10 --ring-port 7000 \
        --manifest /repo/testbed/dns/zones/MANIFEST.json --output /out/B6_proposer_socket.csv
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import random
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
for _p in (str(_REPO_ROOT), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from node.query import _encode                       # noqa: E402  ("ip|ttl")
from node.socket_net import SocketNetwork            # noqa: E402
# reuse A5's deterministic roster + ring-ledger helpers (same addressing contract)
from a5_driver import CLIENT_ID, build_roster, ring_ledger_total, load_domains  # noqa: E402
from node.ids import node_id_from_pk                 # noqa: E402
from node.run_node import _pk_for                    # noqa: E402

FORGED_IP = "6.6.6.6"       # node/malicious.FORGED_IP — the attacker's substituted answer
FORGED_TTL = 300
DEFAULT_SEED = 20260919


def load_answers(manifest: Path) -> dict[str, str]:
    """domain -> correct answer_ip (for the honest-control 'valid' mode)."""
    recs = json.loads(manifest.read_text())["records"]
    return {d: r["answer_ip"] for d, r in recs.items()}


async def run(args) -> None:
    manifest = Path(args.manifest)
    roster = build_roster(args.ring_nodes, args.ring_ip_prefix, args.ring_ip_base, args.ring_port)
    proposer_id = node_id_from_pk(_pk_for(args.proposer))
    domains = load_domains(manifest, args.updates, args.seed)
    answers = load_answers(manifest)
    net = SocketNetwork(CLIENT_ID, roster)

    before = await ring_ledger_total(net, roster, args.timeout)

    committed = 0
    for i, domain in enumerate(domains):
        if args.mode == "forged":
            value = _encode(FORGED_IP, FORGED_TTL)             # INVALID: wrong answer for a real domain
        else:
            value = _encode(answers.get(domain, "203.0.113.1"), args.ttl)   # VALID control
        try:
            res = await net.rpc(CLIENT_ID, proposer_id, "admin_propose",
                                domain, value, "update", timeout=args.timeout)
            if bool(res.get("ok")):
                committed += 1
        except Exception as e:
            print(f"  update {i} ({domain}) FAILED: {e!r}", flush=True)
        if args.interval_ms > 0:
            await asyncio.sleep(args.interval_ms / 1000.0)

    after = await ring_ledger_total(net, roster, args.timeout)

    proposals = len(domains)
    rejected = proposals - committed
    rejection_pct = 100.0 * rejected / proposals if proposals else 0.0
    expected_delta = committed * args.replication
    note = ("forged (invalid) updates committed by honest replicas -> rejection 0 over sockets"
            if args.mode == "forged" else "honest control: valid updates committed")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    new = not out.exists()
    with open(out, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["source", "mode", "ring_nodes", "proposals", "committed", "rejected",
                        "rejection_rate_pct", "ledger_delta", "expected_delta", "note"])
        w.writerow(["socket", args.mode, args.ring_nodes, proposals, committed, rejected,
                    f"{rejection_pct:.4f}", after - before, expected_delta, note])

    print(f"[b6] mode={args.mode} {committed}/{proposals} committed (rejection {rejection_pct:.1f}%); "
          f"ring-wide ledger {before}->{after} (delta {after - before}, expected {expected_delta}) "
          f"-> {out}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="B6 socket cross-check: propose forged/valid updates.")
    ap.add_argument("--ring-nodes", type=int, required=True, help="ring size N")
    ap.add_argument("--mode", choices=["forged", "valid"], default="forged")
    ap.add_argument("--updates", type=int, default=20, help="number of updates to propose")
    ap.add_argument("--proposer", type=int, default=0, help="node index that proposes (default 0)")
    ap.add_argument("--replication", type=int, default=3, help="replication factor s (frozen 3)")
    ap.add_argument("--ring-ip-prefix", default="172.30.0")
    ap.add_argument("--ring-ip-base", type=int, default=10)
    ap.add_argument("--ring-port", type=int, default=7000)
    ap.add_argument("--manifest", default=str(_REPO_ROOT / "testbed/dns/zones/MANIFEST.json"))
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--ttl", type=int, default=300)
    ap.add_argument("--interval-ms", type=float, default=200.0)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--output", default="/out/B6_proposer_socket.csv")
    asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    main()
