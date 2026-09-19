"""Test for sub-issue #14 — PoSpace admission (v3 DRG).

Covers the admission-gated join (honest ring admitted; a node with a bad commitment refused),
the periodic challenge round on an honest ring, and eviction after MAX_FAILS consecutive
failures, plus the admission.csv log. Self-running (no pytest):
`python -m node.tests.test_pospace_admission`.
"""
import asyncio
import csv
import os

from node.pospace_admission import PoSpaceNode, AdmissionError, MAX_FAILS
from node.net import Network
from node.logs import RESULTS_DIR
from node.tests.util import build_ring, run_protocol, ring_is_consistent, pk_for

ADMISSION_PATH = os.path.join(RESULTS_DIR, "admission.csv")


async def _run() -> None:
    # start clean so we can assert on the rows this test writes
    if os.path.exists(ADMISSION_PATH):
        os.remove(ADMISSION_PATH)

    net = Network()
    # (1) every join is admission-gated; build_ring succeeds => all 5 nodes were admitted
    nodes = await build_ring(PoSpaceNode, net, n=5)
    assert all(net.is_up(nd.node_id) for nd in nodes)

    # honest periodic challenge round over the whole ring: all pass, nobody evicted
    for _ in range(3):
        for nd in nodes:
            await nd.challenge_round()
    assert all(net.is_up(nd.node_id) for nd in nodes)
    assert all(sum(nd.fail_counts.values()) == 0 for nd in nodes), \
        [nd.fail_counts for nd in nodes]

    # (2) join refused: a candidate whose commitment does not match its openings cannot be
    #     admitted. join() rebuilds the plot, so wrap _build_plot to corrupt the root after it.
    bad = PoSpaceNode(pk_for(99), net)
    _orig_build = bad._build_plot

    def _broken_build():
        _orig_build()
        bad.plot_root = b"\x00" * 32           # commitment no longer matches its openings

    bad._build_plot = _broken_build
    try:
        await bad.join(nodes[0].node_id)
        assert False, "bad node should have been refused admission"
    except AdmissionError:
        pass
    assert bad.node_id not in net.nodes        # refused node took itself offline
    await run_protocol(nodes, rounds=10)
    assert ring_is_consistent(nodes)           # honest ring unaffected by the refusal

    # (3) eviction: corrupt a victim's plot so every opening fails, then let its predecessor
    #     challenge it MAX_FAILS times in a row.
    victim = nodes[2]
    victim.plot_root = b"\x11" * 32
    victim_id = victim.node_id
    challenger = next(nd for nd in nodes if nd.alive and nd.successor() == victim_id)

    for _ in range(MAX_FAILS):
        await challenger.challenge_round()
    assert challenger.fail_counts.get(victim_id, 0) == 0  # cleared on eviction
    assert victim_id not in net.nodes                     # victim taken offline
    assert not victim.alive

    # the ring heals around the evicted node
    survivors = [nd for nd in nodes if nd.alive]
    await run_protocol(survivors, rounds=20)
    assert ring_is_consistent(survivors)

    # (4) admission.csv has the required header and every event kind
    with open(ADMISSION_PATH) as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["timestamp", "event", "node", "peer", "index",
                       "result", "elapsed_s", "fails"], rows[0]
    events = {r[1] for r in rows[1:]}
    assert {"join_admit", "challenge", "join_refused", "evict"}.issubset(events), events

    for nd in nodes:
        if nd.alive:
            nd.stop()
    print(f"test_pospace_admission: PASS  (5 admitted, bad join refused, victim evicted after "
          f"{MAX_FAILS} fails, ring healed, {len(rows) - 1} rows logged to admission.csv)")


def test_pospace_admission():
    asyncio.run(_run())


if __name__ == "__main__":
    test_pospace_admission()
