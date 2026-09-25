#!/usr/bin/env python3
"""Issue #37 [A6] — churn injector (Phase 6, examiner points (ii)/(iii)).

The testbed has NO graceful leave/depart primitive (node/chord.py has no ``leave()``); the only
realistic node departure is an ungraceful crash, detected by ``node/socket_net.is_up()`` (3
consecutive-failure threshold, 3 s dead_ttl) and healed by ``stabilize``. This host-side driver
supplies that missing churn by ``docker kill`` / ``docker start`` on the ring containers while the
A6 measured load runs — it touches NO protocol code and NO frozen artifact (CLAUDE.md §2), it only
manipulates containers the compose file already created.

Membership model — per-node alternating renewal (the emulation analogue of churn_sim's M/M/∞):
each CHURNABLE node (indices 1..N-1) independently alternates UP ~ Exp(mean_session) then DOWN ~
Exp(mean_downtime), starting UP. So a node departs after an exponential session (== churn_sim's
session-time draw) and rejoins the SAME identity after a short downtime (NODE_INDEX is fixed in the
compose env, so ``docker start`` re-runs the entrypoint and the node re-joins with the same
deterministic pk / ring-id and the same static IP). Node 0 is EXCLUDED from churn — it is the seed /
bootstrap that every rejoin depends on, and queries enter the ring through it (run_a6.sh uses
``--ring-nodes 1``); killing it would break both.

A single seeded min-heap of ``(t_s, seq, action, node)`` events drives the schedule on a wall-clock
timeline (seq breaks ties for reproducibility). Every kill/start is logged with a timestamp and the
resulting live population to ``--events-out`` (schema: ``sim_time_s,event,node,live_pop``), which the
analyser (``experiments/a6_churn.py``) reads for ``mean_live_pop`` and a departure/rejoin count.

Usage (run_a6.sh launches this in the background for the measured window):
  python3 experiments/a6_churn_injector.py --nodes 32 --mean-session 60 --duration 120 \
      --seed 20260919 --events-out results/a6/s60/run1/churn_events.csv

A ``--mean-session inf`` (or <= 0) is the NO-CHURN control: the injector writes an empty events file
and exits immediately, so run_a6.sh can call it uniformly.
"""
from __future__ import annotations

import argparse
import csv
import heapq
import itertools
import math
import random
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_SEED = 20260919
DEFAULT_DOWNTIME_S = 5.0        # mean rejoin gap: a crashed node restarts quickly (documented knob)


def _docker(action: str, name: str) -> bool:
    """Run ``docker <action> <name>``; return True on success. A no-op (already dead/alive) is not
    fatal — we log to stderr and carry on so one flaky call never aborts the churn schedule."""
    try:
        r = subprocess.run(["docker", action, name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        if r.returncode != 0:
            print(f"[injector] docker {action} {name}: rc={r.returncode} "
                  f"{r.stderr.decode(errors='replace').strip()}", file=sys.stderr)
            return False
        return True
    except (subprocess.TimeoutExpired, OSError) as e:      # pragma: no cover
        print(f"[injector] docker {action} {name} failed: {e}", file=sys.stderr)
        return False


def run_injector(*, nodes: int, mean_session_s: float, duration_s: float,
                 mean_downtime_s: float, seed: int, prefix: str,
                 events_out: Path) -> int:
    events_out.parent.mkdir(parents=True, exist_ok=True)

    # NO-CHURN control (session == inf): write an empty events file and return (the ring stays UP).
    if not math.isfinite(mean_session_s) or mean_session_s <= 0:
        with open(events_out, "w", newline="") as f:
            csv.writer(f).writerow(["sim_time_s", "event", "node", "live_pop"])
        print(f"[injector] no-churn control (mean_session={mean_session_s}); "
              f"wrote empty {events_out}", file=sys.stderr)
        return 0

    churnable = list(range(1, nodes))         # node 0 is the seed/bootstrap — never churned
    if not churnable:
        print("[injector] N<=1: nothing churnable", file=sys.stderr)
        with open(events_out, "w", newline="") as f:
            csv.writer(f).writerow(["sim_time_s", "event", "node", "live_pop"])
        return 0

    rng = random.Random(seed ^ 0xC0FFEE)      # same salt churn_sim uses for life draws
    seq = itertools.count()
    heap: list[tuple[float, int, str, int]] = []
    for j in churnable:                        # every churnable node starts UP; first leave ~ Exp
        heapq.heappush(heap, (rng.expovariate(1.0 / mean_session_s), next(seq), "leave", j))

    down: set[int] = set()
    log: list[tuple[float, str, int, int]] = []
    t0 = time.perf_counter()
    print(f"[injector] N={nodes} churnable={len(churnable)} mean_session={mean_session_s}s "
          f"mean_downtime={mean_downtime_s}s duration={duration_s}s seed={seed}", file=sys.stderr)

    while heap:
        t_s, _, action, j = heap[0]
        if t_s > duration_s:
            break
        heapq.heappop(heap)
        # sleep until this event's wall-clock time (relative to start)
        wait = (t0 + t_s) - time.perf_counter()
        if wait > 0:
            time.sleep(wait)
        name = f"{prefix}{j}"
        if action == "leave":
            if _docker("kill", name):
                down.add(j)
            live = nodes - len(down)
            log.append((t_s, "kill", j, live))
            # schedule rejoin after a downtime, then a fresh session after that
            heapq.heappush(heap, (t_s + rng.expovariate(1.0 / mean_downtime_s),
                                  next(seq), "join", j))
        else:  # join
            if _docker("start", name):
                down.discard(j)
            live = nodes - len(down)
            log.append((t_s, "start", j, live))
            heapq.heappush(heap, (t_s + rng.expovariate(1.0 / mean_session_s),
                                  next(seq), "leave", j))

    # restart anything still down so the ring is whole for log-snapshot/teardown (idempotent).
    for j in sorted(down):
        _docker("start", f"{prefix}{j}")

    with open(events_out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sim_time_s", "event", "node", "live_pop"])
        for t_s, ev, j, live in log:
            w.writerow([f"{t_s:.3f}", ev, j, live])

    kills = sum(1 for _, ev, _, _ in log if ev == "kill")
    starts = sum(1 for _, ev, _, _ in log if ev == "start")
    print(f"[injector] done: {kills} kills, {starts} starts over {duration_s}s "
          f"-> {events_out}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="A6 churn injector (issue #37).")
    ap.add_argument("--nodes", type=int, required=True, help="ring size N (node 0 never churns)")
    ap.add_argument("--mean-session", type=float, required=True,
                    help="mean UP session length (s); 'inf'/<=0 => no-churn control")
    ap.add_argument("--duration", type=float, required=True, help="churn window (s)")
    ap.add_argument("--mean-downtime", type=float, default=DEFAULT_DOWNTIME_S,
                    help=f"mean rejoin gap after a kill (s, default {DEFAULT_DOWNTIME_S})")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help=f"RNG seed [{DEFAULT_SEED}]")
    ap.add_argument("--prefix", default="rpos-node-", help="container name prefix")
    ap.add_argument("--events-out", type=Path, required=True, help="churn_events.csv output path")
    args = ap.parse_args()

    return run_injector(nodes=args.nodes, mean_session_s=args.mean_session,
                        duration_s=args.duration, mean_downtime_s=args.mean_downtime,
                        seed=args.seed, prefix=args.prefix, events_out=args.events_out)


if __name__ == "__main__":
    raise SystemExit(main())
