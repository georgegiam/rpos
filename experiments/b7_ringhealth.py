#!/usr/bin/env python3
"""Issue #48 [B7] — ring-health snapshot (Phase 7). Quantifies the chord.py fragility caveat.

Runs inside the ring network (like testbed/finger_probe.py, which it mirrors). Connects to EVERY
node's read-only ``debug_state`` RPC and computes, against brute-force ground truth over the live
ids: the fraction of nodes whose immediate successor (succ_list[0]) is the true ring-next, the
orphan count (wrong/empty successor), and how many have a null predecessor. A flood that starves
chord.py's stabilize makes nodes shed good successors (stabilize drops a successor on any RPC
timeout), so correct_succ_pct FALLS and orphans RISE — the measurable fragility signal B7 reports
beside the honest-client impact (issue #48 "fragility caveat quantified").

Writes a one-object JSON to --output. node/* and rpos/rpos.py untouched (imports/reads only).

    python experiments/b7_ringhealth.py --nodes 32 --output /out/ringhealth.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from node.ids import node_id_from_pk                            # noqa: E402
from node.socket_net import _read_frame, _write_frame          # noqa: E402
from node.tests.util import expected_successor                 # noqa: E402
from experiments.b1_placement import _pk_for                   # noqa: E402 (host-safe identity)


async def _debug_state(host: str, port: int) -> dict:
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


async def run(a) -> int:
    ids = [node_id_from_pk(_pk_for(j)) for j in range(a.nodes)]
    states: dict[int, dict] = {}
    reachable = 0
    for j in range(a.nodes):
        host = f"{a.prefix}.{a.base + j}" if a.prefix[0].isdigit() else f"{a.prefix}{j}"
        try:
            states[j] = await _debug_state(host, a.ring_port)
            reachable += 1
        except Exception:
            states[j] = {}
    live = sorted(ids)
    correct = orphans = pred_none = 0
    for j in range(a.nodes):
        st = states.get(j) or {}
        succ_list = st.get("succ_list") or []
        succ = succ_list[0] if succ_list else None
        want = expected_successor((ids[j] + 1) % (1 << 160), live)
        if succ is not None and succ == want:
            correct += 1
        else:
            orphans += 1
        if st.get("pred") is None:
            pred_none += 1
    out = {
        "nodes": a.nodes, "reachable": reachable,
        "correct_succ_pct": round(100.0 * correct / a.nodes, 4),
        "orphans": orphans, "pred_none": pred_none,
    }
    Path(a.output).parent.mkdir(parents=True, exist_ok=True)
    Path(a.output).write_text(json.dumps(out, indent=2) + "\n")
    print(f"[b7-ringhealth] correct_succ={out['correct_succ_pct']}% orphans={orphans} "
          f"reachable={reachable}/{a.nodes} -> {a.output}", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="B7 ring-health snapshot (issue #48).")
    ap.add_argument("--nodes", type=int, required=True)
    ap.add_argument("--prefix", default="172.30.0", help="static IP /24 prefix OR hostname prefix")
    ap.add_argument("--base", type=int, default=10, help="node 0's last octet (IP addressing)")
    ap.add_argument("--ring-port", type=int, default=7000)
    ap.add_argument("--output", required=True)
    return asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
