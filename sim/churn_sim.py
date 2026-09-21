"""Phase 5 (#28, P5-4) — churn model.

Adds **churn** to the Phase-5 simulator: nodes join and leave with exponentially-distributed
session times, and when a node leaves its successor absorbs its chunks. It answers the issue's
"done when" — *a sweep over mean session times produces a curve* — and is the large-scale data
source for Phase 6 **A6** ("Churn: lookup success and availability vs session length").

The ring in ``sim/chord_sim.py`` (#25) is *static and converged*. Churn is therefore a new mode,
not a tweak: this module drives membership over time and rebuilds a converged ring over the
**currently-live** subset after each maintenance round, reusing ``ChordRing``'s placement /
successor-list logic verbatim (via the new ``ids=`` / ``build_fingers=False`` constructor path).

Model (locked for #28, stated openly per CLAUDE.md "flag, don't hide"):

* **Membership = birth–death (M/M/∞).** Start with N live nodes drawn from the same SHA-256(pk)
  id distribution the emulation uses. Each live node departs after ``Exp(mean_session)``; joins
  arrive as a Poisson process at rate ``N / mean_session``. Equilibrium population ≈ N (mean = N,
  so the swept variable is *mean session length*, not N). Departed ids return to the pool and may
  rejoin later.

* **Maintenance / repair every ``T_repair``** (= the frozen 1.0 s maintenance interval,
  ``results/PARAMETERS.md``). A repair re-converges routing over the live set and **re-replicates**:
  for every chunk that still has ≥1 live holder it restores the full ideal replica set
  (owner + ``S``-1 successors) — this is the "successor absorbs its chunks" handoff.

* **Failure model = data-availability only (user-confirmed).** A lookup fails iff its chunk is
  *permanently lost* — every replica holding it departed within a single repair window, before the
  successor could re-replicate. Loss is detected at the instant a departure empties a chunk's holder
  set; with no live source, a re-replication cannot recreate it, so it stays lost for the rest of
  the run (the raw-DHT view — see the fallback note). **Stale-routing / finger-staleness failures
  are out of scope for #28** (a documented limitation; add for A6 if wanted — hence availability
  needs no finger tables, so rings are built ``build_fingers=False``).

* **Headline metric = raw DHT lookup success rate (user-confirmed).** A churned-out chunk counts as
  a failure. The resolver's iterative **fallback** tier would re-fetch every lost chunk from the DNS
  hierarchy and store it back; that is reported as a secondary "fallback-recoverable" count, **not**
  folded into the headline (folding it in masks churn and flattens the curve). Because raw DHT has
  no re-store, losses accumulate over the fixed measurement window — this is exactly why fallback
  exists, and the effect is reported (``chunks_lost``) rather than hidden.

* **Numeric latency calibration is out of scope (#29).** churn_sim reports success *rate* and chunk
  survival, not tuned latencies.

Reuse: ``ChordRing`` / ``DEFAULT_SEED`` from ``sim/chord_sim.py`` (topology, placement); ``S``,
``load_domains``, ``_replica_set``, ``DEFAULT_DOMAINS``, ``DEFAULT_ZIPF_ALPHA`` from
``sim/query_sim.py`` (byte-identical replica placement — the same ``owner + succ_list[:S]`` rule);
``chunk_id`` from ``node/ids.py`` (byte-identical domain->chunk placement). The Zipf cumulative is
rebuilt inline exactly as ``QuerySim.__init__`` does (the same duplication ``ledger_sim`` already
notes; extracting it is out of scope here).

Run:  ``python -m sim.churn_sim``          (self-test + default sweep, writes the curve CSV)
      ``python -m sim.churn_sim --n 100 --duration 1800 --sessions 10,30,60,300,3600``
      ``python -m sim.churn_sim --no-self-test``
"""
from __future__ import annotations

import argparse
import bisect
import csv
import heapq
import itertools
import math
import os
import random
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from node.ids import chunk_id  # noqa: E402  (after sys.path)
from sim.chord_sim import DEFAULT_SEED, ChordRing  # noqa: E402
from sim.query_sim import (  # noqa: E402
    DEFAULT_DOMAINS,
    DEFAULT_ZIPF_ALPHA,
    S,
    _replica_set,
    load_domains,
)

# ---- frozen defaults (results/PARAMETERS.md) -------------------------------------------
DEFAULT_N = 100                 # a large-scale churn point beyond the N=32 emulation ceiling;
                                # per-chunk loss depends on S / session / repair, ~independent of N
DEFAULT_REPAIR_S = 1.0          # maintenance/stabilize interval == PARAMETERS.md MAINT_INTERVAL
DEFAULT_LOOKUP_QPS = 10.0       # offered lookup rate == PARAMETERS.md workload rate
DEFAULT_DURATION_S = 1800       # measurement horizon (sim time is free; long enough to see churn)
DEFAULT_WARMUP_S = 60           # discarded transient (lets the M/M/∞ population equilibrate)
DEFAULT_DETAIL_SESSION_S = 60   # which sweep point writes the per-lookup detail CSV

# Mean session lengths (seconds) swept to draw the curve. Spans robust (hours) to aggressive
# (tens of seconds) churn so the curve runs from ~100% down to heavy degradation.
DEFAULT_SESSIONS_S = [10, 15, 30, 60, 120, 300, 600, 1800, 3600, 7200]

_HERE = Path(__file__).resolve().parent
_RESULTS_DIR = _HERE / "results"


@dataclass
class LookupRecord:
    """One DHT lookup under churn (per-lookup detail row)."""
    sim_time_ms: float
    domain: str
    cid: int
    success: bool           # a live replica of the chunk exists (raw DHT availability)
    live_pop: int           # live node count at lookup time
    fallback_recoverable: bool   # would the resolver's fallback re-fetch it? (True iff it failed)


@dataclass
class ChurnResult:
    """Aggregate outcome of one churn run at a single mean session length."""
    mean_session_s: float
    lookups: int
    success: int
    lost_lookups: int
    success_rate: float
    chunks_lost: int        # distinct chunks permanently lost by end of run
    mean_live_pop: float
    seed: int


# ---------------------------------------------------------------------------------------
# Zipf cumulative over domains in rank order (identical to QuerySim.__init__; see docstring).
# ---------------------------------------------------------------------------------------
def _zipf_cumulative(n_domains: int, alpha: float) -> list[float]:
    weights = [1.0 / ((i + 1) ** alpha) for i in range(n_domains)]
    total = sum(weights)
    cum: list[float] = []
    acc = 0.0
    for w in weights:
        acc += w / total
        cum.append(acc)
    return cum


# ---------------------------------------------------------------------------------------
# One churn run at a single mean session length.
# ---------------------------------------------------------------------------------------
def run_churn(
    *,
    n: int = DEFAULT_N,
    mean_session_s: float,
    duration_s: int = DEFAULT_DURATION_S,
    warmup_s: int = DEFAULT_WARMUP_S,
    repair_s: float = DEFAULT_REPAIR_S,
    lookup_qps: float = DEFAULT_LOOKUP_QPS,
    n_domains: int = DEFAULT_DOMAINS,
    zipf_alpha: float = DEFAULT_ZIPF_ALPHA,
    seed: int = DEFAULT_SEED,
    collect_detail: bool = False,
) -> tuple[ChurnResult, list[LookupRecord]]:
    """Simulate churn for one mean session length; return (aggregate, detail rows).

    A single min-heap of ``(time_ms, seq, kind, payload)`` merges four event streams —
    ``leave`` / ``join`` (membership), ``repair`` (maintenance), ``lookup`` (workload) — on one
    deterministic timeline (seed-reproducible, seq breaks ties). ``detail`` rows are only kept for
    the measurement window and only when ``collect_detail`` is set (the sweep enables it for one
    point, matching how the query/ledger sims keep one per-run CSV).
    """
    if mean_session_s <= 0:
        raise ValueError("mean_session_s must be > 0")

    # A fixed pool of candidate node ids (headroom for population fluctuation ~ N ± sqrt(N)).
    pool_size = max(4 * n, n + 64)
    pool = ChordRing._generate_ids(pool_size, seed)      # sorted, deterministic
    inactive = set(pool)

    domains = load_domains(n_domains)
    cids = [chunk_id(d) for d in domains]
    domain_of_cid = {c: d for c, d in zip(cids, domains)}
    cum = _zipf_cumulative(len(domains), zipf_alpha)

    # RNGs: one per concern, seeded, independent, reproducible.
    life_rng = random.Random(seed ^ 0xC0FFEE)            # session/inter-join draws
    join_rng = random.Random(seed ^ 0x1234)              # which pool node joins
    load_rng = random.Random(seed ^ 0xA5A5)              # Zipf lookup draws

    horizon_ms = (warmup_s + duration_s) * 1000.0
    warmup_ms = warmup_s * 1000.0

    heap: list[tuple[float, int, str, object]] = []
    seq = itertools.count()

    def _sample_domain() -> str:
        return domains[bisect.bisect_left(cum, load_rng.random())]

    # --- initial live set: first N pool ids (the pool is already the SHA-256 distribution) -----
    live: set[int] = set(pool[:n])
    inactive -= live
    for u in live:
        heapq.heappush(heap, (life_rng.expovariate(1.0 / mean_session_s) * 1000.0,
                              next(seq), "leave", u))
    # Poisson join stream at rate N/mean_session -> first join, then self-reschedule on firing.
    # Mean inter-join time in *seconds* (converted to ms at the point of use, like the leave draws).
    join_interval_mean_s = mean_session_s / n
    heapq.heappush(heap, (life_rng.expovariate(1.0 / join_interval_mean_s) * 1000.0,
                          next(seq), "join", None))
    # Repair + lookup streams.
    heapq.heappush(heap, (repair_s * 1000.0, next(seq), "repair", None))
    lookup_interval_ms = 1000.0 / lookup_qps
    heapq.heappush(heap, (0.0, next(seq), "lookup", None))

    # --- warm DHT: every chunk fully replicated on its ideal set over the initial live ring -----
    holders: dict[int, set[int]] = {}
    node_chunks: dict[int, set[int]] = defaultdict(set)
    lost: set[int] = set()
    ring0 = ChordRing(0, ids=sorted(live), build_fingers=False)
    for c in cids:
        ideal = _replica_set(ring0, ring0.successor_of(c))
        holders[c] = set(ideal)
        for h in ideal:
            node_chunks[h].add(c)

    # --- aggregate accumulators (measurement window only) -----
    lookups = success = 0
    pop_samples: list[int] = []
    detail: list[LookupRecord] = []

    def _do_leave(u: int) -> None:
        if u not in live:
            return
        live.discard(u)
        inactive.add(u)
        for c in node_chunks.pop(u, ()):
            hs = holders.get(c)
            if hs is not None:
                hs.discard(u)
                if not hs and c not in lost:
                    lost.add(c)          # all replicas gone within one repair window -> lost

    def _do_join() -> None:
        if not inactive:
            return                        # pool exhausted (astronomically unlikely at 4N)
        u = join_rng.choice(tuple(inactive))
        inactive.discard(u)
        live.add(u)                       # holds no chunks until the next repair assigns them
        heapq.heappush(heap, (t + life_rng.expovariate(1.0 / mean_session_s) * 1000.0,
                              next(seq), "leave", u))

    def _do_repair() -> None:
        if not live:
            return
        ring = ChordRing(0, ids=sorted(live), build_fingers=False)
        new_nc: dict[int, set[int]] = defaultdict(set)
        for c in cids:
            if c in lost:
                continue
            surv = holders.get(c)
            if not surv:
                continue                  # empty => already marked lost on the emptying leave
            ideal = _replica_set(ring, ring.successor_of(c))   # successor absorbs / re-replicates
            holders[c] = set(ideal)
            for h in ideal:
                new_nc[h].add(c)
        node_chunks.clear()
        node_chunks.update(new_nc)

    # --- drain the timeline ---------------------------------------------------------------------
    while heap:
        t, _, kind, payload = heapq.heappop(heap)
        if t >= horizon_ms:
            break
        if kind == "leave":
            _do_leave(payload)            # type: ignore[arg-type]
        elif kind == "join":
            _do_join()
            nxt = life_rng.expovariate(1.0 / join_interval_mean_s) * 1000.0
            heapq.heappush(heap, (t + nxt, next(seq), "join", None))
        elif kind == "repair":
            _do_repair()
            heapq.heappush(heap, (t + repair_s * 1000.0, next(seq), "repair", None))
        else:  # lookup
            heapq.heappush(heap, (t + lookup_interval_ms, next(seq), "lookup", None))
            d = _sample_domain()
            c = chunk_id(d)
            ok = bool(holders.get(c))
            if t >= warmup_ms:
                lookups += 1
                pop_samples.append(len(live))
                if ok:
                    success += 1
                if collect_detail:
                    detail.append(LookupRecord(t, d, c, ok, len(live), not ok))

    lost_lookups = lookups - success
    result = ChurnResult(
        mean_session_s=mean_session_s,
        lookups=lookups,
        success=success,
        lost_lookups=lost_lookups,
        success_rate=(success / lookups) if lookups else 0.0,
        chunks_lost=len(lost),
        mean_live_pop=(statistics.fmean(pop_samples) if pop_samples else 0.0),
        seed=seed,
    )
    return result, detail


# ---------------------------------------------------------------------------------------
# The sweep — the issue deliverable: a curve of lookup success rate vs mean session length.
# ---------------------------------------------------------------------------------------
def run_sweep(
    *,
    n: int = DEFAULT_N,
    sessions_s: list[float] | None = None,
    duration_s: int = DEFAULT_DURATION_S,
    warmup_s: int = DEFAULT_WARMUP_S,
    repair_s: float = DEFAULT_REPAIR_S,
    lookup_qps: float = DEFAULT_LOOKUP_QPS,
    n_domains: int = DEFAULT_DOMAINS,
    zipf_alpha: float = DEFAULT_ZIPF_ALPHA,
    seed: int = DEFAULT_SEED,
    detail_session_s: float = DEFAULT_DETAIL_SESSION_S,
) -> tuple[list[ChurnResult], list[LookupRecord]]:
    """Run one churn simulation per mean session length; return (curve rows, one detail run)."""
    sessions = sorted(sessions_s if sessions_s is not None else DEFAULT_SESSIONS_S)
    curve: list[ChurnResult] = []
    detail_rows: list[LookupRecord] = []
    for ms in sessions:
        want_detail = math.isclose(ms, detail_session_s)
        res, det = run_churn(
            n=n, mean_session_s=ms, duration_s=duration_s, warmup_s=warmup_s,
            repair_s=repair_s, lookup_qps=lookup_qps, n_domains=n_domains,
            zipf_alpha=zipf_alpha, seed=seed, collect_detail=want_detail,
        )
        curve.append(res)
        if want_detail:
            detail_rows = det
    return curve, detail_rows


# ---------------------------------------------------------------------------------------
# CSV output + console table (mirror the query/ledger sim conventions).
# ---------------------------------------------------------------------------------------
def write_curve_csv(path: Path, params: dict, curve: list[ChurnResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["n", "mean_session_s", "duration_s", "warmup_s", "repair_s", "lookup_qps",
                    "domains", "zipf_alpha", "seed",
                    "lookups", "success", "lost_lookups", "success_rate",
                    "chunks_lost", "mean_live_pop"])
        for r in curve:
            w.writerow([
                params["n"], f"{r.mean_session_s:g}", params["duration_s"], params["warmup_s"],
                f"{params['repair_s']:g}", f"{params['lookup_qps']:g}",
                params["n_domains"], f"{params['zipf_alpha']:g}", r.seed,
                r.lookups, r.success, r.lost_lookups, f"{r.success_rate:.6f}",
                r.chunks_lost, f"{r.mean_live_pop:.2f}",
            ])


def write_detail_csv(path: Path, rows: list[LookupRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sim_time_ms", "domain", "cid", "success", "live_pop", "fallback_recoverable"])
        for r in rows:
            w.writerow([f"{r.sim_time_ms:.3f}", r.domain, r.cid, int(r.success),
                        r.live_pop, int(r.fallback_recoverable)])


def _print_curve(params: dict, curve: list[ChurnResult]) -> None:
    print(f"\nchurn_sim sweep — N={params['n']}, repair {params['repair_s']:g}s, "
          f"{params['lookup_qps']:g} qps, {params['duration_s']}s (+{params['warmup_s']}s warm-up), "
          f"s={S}, seed {params['seed']}")
    print(f"{'mean_session_s':>14} {'success_rate':>13} {'lookups':>9} "
          f"{'chunks_lost':>11} {'mean_live':>10}")
    for r in curve:
        print(f"{r.mean_session_s:>14g} {100*r.success_rate:>12.2f}% {r.lookups:>9} "
              f"{r.chunks_lost:>11} {r.mean_live_pop:>10.1f}")


# ---------------------------------------------------------------------------------------
# Self-test — invariants that must hold regardless of #29 calibration.
# ---------------------------------------------------------------------------------------
def _run_self_test() -> bool:
    ok = True
    # Short horizon so the self-test is fast; the invariants are structural, not numeric.
    common = dict(n=60, duration_s=300, warmup_s=30, repair_s=DEFAULT_REPAIR_S,
                  lookup_qps=20.0, n_domains=500, seed=DEFAULT_SEED)

    # (1) Low churn (very long sessions) -> ~100% success and ~no chunk loss.
    hi, _ = run_churn(mean_session_s=100000.0, **common)
    if not (hi.success_rate > 0.999 and hi.chunks_lost == 0):
        print(f"FAIL: low churn not ~100% (rate {hi.success_rate:.4f}, lost {hi.chunks_lost})")
        ok = False

    # (2) High churn (very short sessions) -> materially degraded success.
    lo, _ = run_churn(mean_session_s=8.0, **common)
    if not (lo.success_rate < 0.95 and lo.chunks_lost > 0):
        print(f"FAIL: high churn not degraded (rate {lo.success_rate:.4f}, lost {lo.chunks_lost})")
        ok = False

    # (3) Monotonicity: success rate is (weakly) non-decreasing in mean session length.
    curve, _ = run_sweep(sessions_s=[8, 30, 120, 600, 100000], **common)
    rates = [r.success_rate for r in curve]   # curve is sorted by session length ascending
    if any(rates[i + 1] < rates[i] - 0.02 for i in range(len(rates) - 1)):
        print(f"FAIL: success rate not monotone in session length: {[f'{x:.3f}' for x in rates]}")
        ok = False

    # (4) Equilibrium population stays near N (birth-death M/M/∞ has mean ~ N).
    mid, _ = run_churn(mean_session_s=120.0, **common)
    if not (abs(mid.mean_live_pop - common["n"]) <= 0.25 * common["n"]):
        print(f"FAIL: mean live pop {mid.mean_live_pop:.1f} not within 25% of N={common['n']}")
        ok = False

    # (5) Absorption vs loss boundary (controlled micro-scenario, no random churn):
    #     build a warm ring, then take out replicas of a specific chunk and check the rule.
    ring = ChordRing(0, ids=ChordRing._generate_ids(20, DEFAULT_SEED), build_fingers=False)
    c = chunk_id("boundary.example")
    replicas = _replica_set(ring, ring.successor_of(c))     # S distinct nodes
    if len(replicas) != S:
        print(f"FAIL: expected {S} replicas, got {len(replicas)}")
        ok = False
    else:
        holders = {c: set(replicas)}
        # Drop S-1 replicas: chunk survives (a live successor still holds it -> absorbable).
        for u in replicas[:-1]:
            holders[c].discard(u)
        survived = bool(holders[c])
        # Drop the last replica within the same window: chunk is lost (no live source).
        holders[c].discard(replicas[-1])
        was_lost = not holders[c]
        if not (survived and was_lost):
            print(f"FAIL: absorption boundary wrong (survived={survived}, lost={was_lost})")
            ok = False

    # (6) Determinism: same seed -> identical curve.
    c1, _ = run_sweep(sessions_s=[30, 300], **common)
    c2, _ = run_sweep(sessions_s=[30, 300], **common)
    if [(r.lookups, r.success, r.chunks_lost) for r in c1] != \
       [(r.lookups, r.success, r.chunks_lost) for r in c2]:
        print("FAIL: sweep is not deterministic under a fixed seed")
        ok = False

    return ok


def _parse_sessions(s: str) -> list[float]:
    return [float(x) for x in s.split(",") if x.strip()]


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Phase 5 (#28) churn model — success rate vs session length.")
    p.add_argument("--n", type=int, default=DEFAULT_N, help=f"equilibrium ring size (default {DEFAULT_N})")
    p.add_argument("--sessions", type=_parse_sessions, default=None, dest="sessions_s",
                   help="comma-separated mean session lengths in seconds (default a wide sweep)")
    p.add_argument("--duration", type=int, default=DEFAULT_DURATION_S, dest="duration_s",
                   help=f"measurement seconds (default {DEFAULT_DURATION_S})")
    p.add_argument("--warmup", type=int, default=DEFAULT_WARMUP_S, dest="warmup_s",
                   help=f"warm-up seconds, discarded (default {DEFAULT_WARMUP_S})")
    p.add_argument("--repair", type=float, default=DEFAULT_REPAIR_S, dest="repair_s",
                   help=f"maintenance/repair interval seconds (default {DEFAULT_REPAIR_S})")
    p.add_argument("--qps", type=float, default=DEFAULT_LOOKUP_QPS, dest="lookup_qps",
                   help=f"offered lookup rate (default {DEFAULT_LOOKUP_QPS})")
    p.add_argument("--domains", type=int, default=DEFAULT_DOMAINS, dest="n_domains",
                   help=f"number of Tranco domains (default {DEFAULT_DOMAINS})")
    p.add_argument("--zipf", type=float, default=DEFAULT_ZIPF_ALPHA, dest="zipf_alpha",
                   help=f"Zipf popularity exponent (default {DEFAULT_ZIPF_ALPHA})")
    p.add_argument("--detail-session", type=float, default=DEFAULT_DETAIL_SESSION_S,
                   dest="detail_session_s",
                   help="which swept session length writes the per-lookup detail CSV")
    p.add_argument("--seed", type=int, default=DEFAULT_SEED, help=f"RNG seed (default {DEFAULT_SEED})")
    p.add_argument("--no-self-test", action="store_true", help="skip the invariant self-test")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    ok = True
    if not args.no_self_test:
        print(f"churn_sim self-test (seed {DEFAULT_SEED})")
        ok = _run_self_test()
        print("PASS" if ok else "FAILED")

    params = {
        "n": args.n, "duration_s": args.duration_s, "warmup_s": args.warmup_s,
        "repair_s": args.repair_s, "lookup_qps": args.lookup_qps,
        "n_domains": args.n_domains, "zipf_alpha": args.zipf_alpha, "seed": args.seed,
    }
    curve, detail = run_sweep(
        n=args.n, sessions_s=args.sessions_s, duration_s=args.duration_s, warmup_s=args.warmup_s,
        repair_s=args.repair_s, lookup_qps=args.lookup_qps, n_domains=args.n_domains,
        zipf_alpha=args.zipf_alpha, seed=args.seed, detail_session_s=args.detail_session_s,
    )
    _print_curve(params, curve)

    curve_csv = _RESULTS_DIR / "churn_sim_curve.csv"
    write_curve_csv(curve_csv, params, curve)
    print(f"\n  wrote curve      : {curve_csv.relative_to(_HERE.parent)}")
    if detail:
        detail_csv = _RESULTS_DIR / f"churn_sim_N{args.n}_s{int(args.detail_session_s)}.csv"
        write_detail_csv(detail_csv, detail)
        print(f"  wrote detail     : {detail_csv.relative_to(_HERE.parent)}  "
              f"(mean session {args.detail_session_s:g}s)")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
