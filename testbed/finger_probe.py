"""Diagnostic: read live ring nodes' finger tables and report convergence % (Phase 3 scale).

Runs inside the ring network. Derives every node id from N (deterministic pk_for, same rule as
run_ring_node), opens the socket transport to a few sample nodes, calls the read-only
``debug_state`` RPC, and compares each of the M=160 finger slots to brute-force ground truth
(the true successor of ``node_id + 2**i``). Prints, per node, the fraction of fingers that are
correct and the distinct useful fingers present.
"""
import argparse
import asyncio
import random

from node.chord import M
from node.ids import RING_SIZE, node_id_from_pk
from node.run_node import _pk_for
from node.socket_net import _read_frame, _write_frame
from node.tests.util import expected_successor


async def _debug_state(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    try:
        await _write_frame(writer, ("REQ", 0, "debug_state", ()))
        tag, payload = await _read_frame(reader)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    if tag != "OK":
        raise RuntimeError(f"debug_state failed: {payload}")
    return payload


def _finger_pct(node_id, fingers, live_ids):
    correct = 0
    want_set = set()
    for i in range(M):
        want = expected_successor((node_id + (1 << i)) % RING_SIZE, live_ids)
        want_set.add(want)
        if fingers[i] == want:
            correct += 1
    have = {f for f in fingers if f != node_id}
    useful = len((have & want_set) - {node_id})
    need = len(want_set - {node_id})
    return correct, useful, need


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", type=int, required=True)
    ap.add_argument("--prefix", default="rpos-node-")
    ap.add_argument("--ring-port", type=int, default=7000)
    ap.add_argument("--sample", type=int, default=3)
    ap.add_argument("--seed", type=int, default=99)
    a = ap.parse_args()

    ids = [node_id_from_pk(_pk_for(j)) for j in range(a.nodes)]
    idx = random.Random(a.seed).sample(range(a.nodes), a.sample)
    print(f"finger convergence at N={a.nodes} (sample nodes {sorted(idx)}):")
    for j in sorted(idx):
        host = f"{a.prefix}{j}"
        try:
            st = await _debug_state(host, a.ring_port)
        except Exception as e:
            print(f"  node-{j}: probe failed: {e!r}")
            continue
        c, useful, need = _finger_pct(st["node_id"], st["fingers"], ids)
        pred = "set" if st["pred"] is not None else "None"
        print(f"  node-{j}: fingers correct {c}/{M} ({100*c/M:.0f}%) | "
              f"distinct-useful {useful}/{need} | succ_list={len(st['succ_list'])} | pred={pred}")


if __name__ == "__main__":
    asyncio.run(main())
