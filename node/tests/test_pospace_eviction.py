"""Check 3 — PoSpace eviction after MAX_FAILS consecutive failed challenges.

A victim node's plot is corrupted so its openings no longer match its published commitment:
every challenge it answers fails verify_v3 (a proof with wrong labels). Its predecessor
challenges it MAX_FAILS (=3) times in a row; on the third failure the challenger must evict it —
taking it offline (removed from the ring / marked inactive). We assert:

  * fail count climbs 1, 2, 3 across the three rounds;
  * after the third, the victim is gone from the network registry and `alive` is False;
  * the surviving ring heals around it.

Self-running (no pytest): `python -m node.tests.test_pospace_eviction`.
"""
import asyncio

from node.net import Network
from node.pospace_admission import PoSpaceNode, MAX_FAILS
from node.tests.util import build_ring, run_protocol, ring_is_consistent


async def _run() -> None:
    net = Network()
    nodes = await build_ring(PoSpaceNode, net, n=5)
    assert ring_is_consistent(nodes), "ring did not converge"

    # --- pick a victim and corrupt its plot so every opening fails verification ---
    victim = nodes[2]
    victim_id = victim.node_id
    victim.plot_root = b"\x11" * 32          # commitment no longer matches the real openings

    # its predecessor (the node whose immediate successor is the victim) does the challenging
    challenger = next(nd for nd in nodes if nd.alive and nd.successor() == victim_id)
    assert challenger.node_id != victim_id

    # --- fail 3 challenges in a row; count must climb 1 -> 2 -> 3, no eviction before the 3rd ---
    for round_no in range(1, MAX_FAILS + 1):
        ok = await challenger.challenge_peer(victim_id)
        assert ok is False, f"round {round_no}: corrupted victim unexpectedly passed"
        if round_no < MAX_FAILS:
            assert challenger.fail_counts.get(victim_id, 0) == round_no, \
                (round_no, challenger.fail_counts.get(victim_id, 0))
            assert net.is_up(victim_id), f"victim evicted too early at round {round_no}"

    # --- after MAX_FAILS: the victim must be evicted (offline + out of the ring) ---
    assert not net.is_up(victim_id), "EVICTION FAILED: victim still up after MAX_FAILS"
    assert victim_id not in net.nodes, "EVICTION FAILED: victim still in the network registry"
    assert victim.alive is False, "EVICTION FAILED: victim still marked alive"
    # eviction clears the challenger's counter and drops the victim from its successor list
    assert challenger.fail_counts.get(victim_id, 0) == 0, "fail count not cleared on eviction"
    assert victim_id not in challenger.successor_list, "victim still in challenger succ-list"

    # --- the ring heals around the evicted node ---
    survivors = [nd for nd in nodes if nd.alive]
    assert len(survivors) == 4
    await run_protocol(survivors, rounds=20)
    assert ring_is_consistent(survivors), "ring did not heal after eviction"

    for nd in survivors:
        nd.stop()
    print(f"test_pospace_eviction: PASS  (victim failed {MAX_FAILS} challenges, was evicted "
          f"and taken offline, ring healed to {len(survivors)} nodes)")


def test_pospace_eviction() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    test_pospace_eviction()
