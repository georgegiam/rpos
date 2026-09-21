"""Phase 5 (#27, P5-3) — ledger + update simulation.

Models the resolver's **write path** — Algorithm 3, the chunk ledger's two-phase commit
(``node/ledger.py`` ``propose_update``) — and **TTL-expiry-driven re-resolution**
(``refresh_expired``), on top of the converged Chord ring from ``sim/chord_sim.py`` (#25).
It is the large-scale companion to the read-path sim (``sim/query_sim.py``, #26) and the data
source Phase 6 A5 ("updates: commit latency, messages per update, ledger growth") draws on.

For each update it reproduces what the emulation resolver does:

    1. locate the replica set: route to the primary + one ``get_succ_list`` RTT
    2. PRE-COMMIT: one round-trip to each of the s replicas (majority of yes votes needed)
    3. COMMIT (on majority): one round-trip to each replica; each appends one hash-chain entry

and emits per-update **latency** and **message count** (issue #27's "done when"), plus the
outcome mix (committed / aborted) and cumulative ledger growth. A ``ttl_refresh`` additionally
pays the upstream re-resolution cost (the fallback referral chain) before its 2PC.

Design choices (locked for #27, stated openly per CLAUDE.md "flag, don't hide"):

* **Each phase is one round-trip to s replicas, modelled as parallel fan-out (``max`` RTT).**
  This matches the issue's framing and how ``query_sim`` already models replica reads/writes.
  The real ``propose_update`` issues the per-replica calls **sequentially** in a for-loop, so
  true per-phase latency is the ``sum`` of the replica RTTs; parallel is a lower bound,
  sequential an upper bound. Self-test (8) asserts parallel <= sequential so the gap is explicit.

* **No node/link failures are modelled**, so the open-loop workload produces only committed
  updates (there are no concurrent proposers contending for the same chunk lock). The abort
  path — pre-commit fails on a lock conflict, s abort RPCs instead of the commit round — is
  implemented and exercised by the self-test (injected lock conflict), not by the workload.

* **TTL refresh is driven by the primary and re-runs Chord's owner-lookup.** In ``refresh_expired``
  only the chunk's primary refreshes, and it re-resolves via the upstream hierarchy then re-commits
  through the same 2PC. We set the proposer to the primary and charge the locate hops of
  ``route(primary, cid)`` — which is Chord's owner-lookup worst case (median ~4 vs ~2 for a random
  origin at N=32), faithfully reproducing the ``find_successor(cid)`` the primary itself runs.

* **Model only — numeric calibration is deferred to #29.** All per-leg delay weights are the same
  named constants ``query_sim`` uses (imported, single source of truth), seeded from the frozen
  ``chord_sim`` / ``PARAMETERS.md`` figures; they are NOT tuned to any measured update latency
  (there is no emulation update-latency baseline — this establishes the model, #29 calibrates it).

* **Long horizon is sim-time only.** Zone TTLs are 300–3600 s, so nothing expires in a 30 s window;
  the default horizon is 7200 s of *simulated* time (which is free) purely so the TTL ladder
  actually expires and each domain refreshes several times. A warm-up window is still discarded,
  mirroring the emulation methodology (seed 20260919).

Reuse: ``ChordRing`` / ``RouteResult`` / ``lookup_latency`` / ``DEFAULT_SEED`` from
``sim/chord_sim.py`` (topology, routing, per-hop delay); ``chunk_id`` from ``node/ids.py``
(byte-identical domain->chunk placement); and — so replica placement and per-leg RTT costs are
identical to the query sim (critical for #29) — ``S``, ``FALLBACK_STEPS``, ``FALLBACK_STEP_MS``,
``VOTE_PROC_MS``, ``TTL_LADDER_S`` and the helpers ``_rpc_rtt_ms`` / ``_route_latency_ms`` /
``_replica_set`` / ``load_domains`` / ``_percentile`` from ``sim/query_sim.py``. This makes
``ledger_sim`` depend on its sibling ``query_sim`` (deliberate calibration coupling). The Zipf
distribution builder and per-domain TTL assignment live inside ``QuerySim.__init__`` (not module
helpers) and so are duplicated in ``LedgerSim.__init__``; extracting them is out of scope for #27.
``node/ledger.py`` is not imported (it is async, bound to the message bus); its logic is ported.

Run:  ``python -m sim.ledger_sim``          (self-test + default N=32 workload, writes CSVs)
      ``python -m sim.ledger_sim --n 32 --update-qps 1 --duration 7200 --warmup 30``
      ``python -m sim.ledger_sim --update-qps 0``   (pure TTL-refresh characterization)
"""
from __future__ import annotations

import argparse
import csv
import heapq
import itertools
import math
import os
import random
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from node.ids import chunk_id  # noqa: E402  (after sys.path)
from sim.chord_sim import (  # noqa: E402
    DEFAULT_SEED,
    ChordRing,
    lookup_latency,
)
from sim.query_sim import (  # noqa: E402  — single source of truth for placement + per-leg cost
    FALLBACK_STEP_MS,
    FALLBACK_STEPS,
    TTL_LADDER_S,
    VOTE_PROC_MS,
    _percentile,
    _replica_set,
    _route_latency_ms,
    _rpc_rtt_ms,
    load_domains,
)

# ---- workload defaults (mirror results/PARAMETERS.md) ----------------------------------
DEFAULT_N = 32
DEFAULT_UPDATE_QPS = 1.0        # client-initiated updates (Zipf); TTL refreshes are separate
DEFAULT_DURATION_S = 7200       # 2 h sim horizon so 300–3600 s TTLs expire (sim time is free)
DEFAULT_WARMUP_S = 30           # discarded window (seed commits land at t=0 and are discarded)
DEFAULT_DOMAINS = 1000
DEFAULT_ZIPF_ALPHA = 1.0

_HERE = Path(__file__).resolve().parent
_RESULTS_DIR = _HERE / "results"


@dataclass
class UpdateRecord:
    """One Algorithm-3 run: what the emulation logs per update, plus latency and message count."""
    sim_time_ms: float      # event time on the sim clock
    domain: str
    proposer: str           # "node-<sorted index>" (client for update; primary for ttl_refresh)
    action: str             # update | ttl_refresh
    outcome: str            # committed | aborted | partial
    replicas: int           # k = len(replica_set)
    hops: int               # locate hops (route to primary), logged separately so they subtract
    precommit_yes: int
    commit_ok: int
    round_trips: int        # protocol round-trips (see propose)
    messages: int           # 2 * round_trips
    entries_appended: int   # hash-chain entries this update added ring-wide (== commit_ok)
    ledger_len: int         # cumulative ring-wide committed entries after this update (A5)
    latency_ms: float


# ---------------------------------------------------------------------------------------
# The ledger/update simulator — analytic port of node/ledger.py Algorithm 3.
# ---------------------------------------------------------------------------------------
class LedgerSim:
    """Holds ring + ledger state and runs Algorithm 3's two-phase commit per update."""

    def __init__(
        self,
        ring: ChordRing,
        domains: list[str],
        *,
        zipf_alpha: float = DEFAULT_ZIPF_ALPHA,
        seed: int = DEFAULT_SEED,
        fallback_steps: int = FALLBACK_STEPS,
        fallback_step_ms: float = FALLBACK_STEP_MS,
    ) -> None:
        self.ring = ring
        self.domains = domains
        self.fallback_steps = fallback_steps
        self.fallback_step_ms = fallback_step_ms

        # Analytic mirrors of LedgerMixin state.
        self.pending: dict[int, str] = {}        # cid -> proposal id currently locked
        self.expiry: dict[int, float] = {}       # cid -> expiry on the sim clock (ms)
        self.chunk_domain: dict[int, str] = {}   # cid -> domain
        self.ledger_len: int = 0                 # cumulative ring-wide committed entries

        # Per-domain TTL (seeded, deterministic) from the zone TTL ladder — same construction as
        # QuerySim (kept in sync; the builder is not a shared helper, see the module docstring).
        trng = random.Random(seed ^ 0x77)
        self.ttl_ms: dict[str, float] = {d: 1000.0 * trng.choice(TTL_LADDER_S) for d in domains}

        # Zipf(alpha) cumulative distribution over domains in rank order (rank 1 = most popular).
        weights = [1.0 / ((i + 1) ** zipf_alpha) for i in range(len(domains))]
        total = sum(weights)
        self._cum: list[float] = []
        acc = 0.0
        for w in weights:
            acc += w / total
            self._cum.append(acc)

    # ---- workload sampling ----
    def sample_domain(self, rng: random.Random) -> str:
        """Draw a domain by Zipf popularity (popular domains updated/refreshed more often)."""
        import bisect
        return self.domains[bisect.bisect_left(self._cum, rng.random())]

    def random_origin(self, rng: random.Random) -> int:
        """Update ingress node, uniform over the ring."""
        return rng.choice(self.ring.ids)

    def primary_of(self, domain: str) -> int:
        """The chunk's primary == successor_of(chunk_id) in the converged ring."""
        return self.ring.successor_of(chunk_id(domain))

    # ---- replica-side handler mirrors (node/ledger.py) ----
    @staticmethod
    def _pid(origin_pos: int, action: str, now_ms: float) -> str:
        """A deterministic proposal id (reproducible; the workload is single-proposer)."""
        return f"{origin_pos}|{action}|{now_ms:.3f}"

    def _precommit_ok(self, cid: int, pid: str) -> bool:
        """Mirror _h_precommit: vote no if already locked for a different proposal, else lock."""
        locked = self.pending.get(cid)
        if locked is not None and locked != pid:
            return False
        self.pending[cid] = pid
        return True

    def _commit(self, cid: int, domain: str, now_ms: float, k: int) -> int:
        """Mirror _h_commit across k replicas: append k chain entries, set expiry, release lock."""
        self.ledger_len += k
        self.expiry[cid] = now_ms + self.ttl_ms[domain]
        self.chunk_domain[cid] = domain
        self.pending.pop(cid, None)
        return k

    # ---- the update path (analytic port of node/ledger.py propose_update) ----
    def propose(self, origin: int, domain: str, action: str, now_ms: float) -> UpdateRecord:
        ring = self.ring
        cid = chunk_id(domain)
        proposer_label = f"node-{ring.pos[origin]}"

        # Locate the replica set: route to the primary + one get_succ_list RTT (storage.replica_set).
        rr = ring.route(origin, cid)
        primary = rr.responsible
        replicas = _replica_set(ring, primary)
        k = len(replicas)
        majority = k // 2 + 1
        route_lat = _route_latency_ms(ring, rr)
        succ_rtt = _rpc_rtt_ms(ring, origin, primary)

        # A ttl_refresh first re-resolves via the upstream hierarchy (fallback referral chain).
        fallback_lat = self.fallback_steps * self.fallback_step_ms if action == "ttl_refresh" else 0.0

        # Phase 1 — pre-commit (one round-trip to each replica, parallel fan-out -> max RTT).
        pid = self._pid(ring.pos[origin], action, now_ms)
        precommit_lat = max((_rpc_rtt_ms(ring, origin, r) for r in replicas), default=0.0)
        precommit_yes = k if self._precommit_ok(cid, pid) else 0   # single-proposer: all-or-nothing

        locate_rt = rr.hops + 1                                    # lookup hops + get_succ_list RTT

        if precommit_yes >= majority:
            # Phase 2 — commit (one round-trip to each replica; each appends a hash-chain entry).
            commit_lat = max((_rpc_rtt_ms(ring, origin, r) for r in replicas), default=0.0)
            commit_ok = k
            entries = self._commit(cid, domain, now_ms, k)
            outcome = "committed"
            latency = fallback_lat + route_lat + succ_rtt + precommit_lat + VOTE_PROC_MS + commit_lat
            round_trips = locate_rt + 2 * k                       # precommit k + commit k
        else:
            # Abort — pre-commit failed; s abort RPCs instead of the commit round. The lock is held
            # by another proposal, so (mirroring _h_abort) we do not release it.
            commit_ok = 0
            entries = 0
            outcome = "aborted"
            latency = fallback_lat + route_lat + succ_rtt + precommit_lat + VOTE_PROC_MS
            round_trips = locate_rt + 2 * k                       # precommit k + abort k

        return UpdateRecord(
            sim_time_ms=now_ms, domain=domain, proposer=proposer_label, action=action,
            outcome=outcome, replicas=k, hops=rr.hops, precommit_yes=precommit_yes,
            commit_ok=commit_ok, round_trips=round_trips, messages=2 * round_trips,
            entries_appended=entries, ledger_len=self.ledger_len, latency_ms=latency,
        )


# ---------------------------------------------------------------------------------------
# Workload runner — TTL expiry -> re-resolution, merged with a client-update stream.
# ---------------------------------------------------------------------------------------
def run_workload(
    *,
    n: int = DEFAULT_N,
    update_qps: float = DEFAULT_UPDATE_QPS,
    duration_s: int = DEFAULT_DURATION_S,
    warmup_s: int = DEFAULT_WARMUP_S,
    n_domains: int = DEFAULT_DOMAINS,
    zipf_alpha: float = DEFAULT_ZIPF_ALPHA,
    seed: int = DEFAULT_SEED,
) -> tuple[LedgerSim, list[UpdateRecord]]:
    """Run the update workload; return (sim, measurement-window records).

    Two event streams share one timeline via a min-heap of (event_time_ms, seq, kind, domain):
      * "expiry" — a committed chunk's TTL runs out; the primary re-resolves and re-commits.
      * "update" — a client-initiated record change at ``update_qps`` (Zipf domain, random origin).
    Every commit reschedules the chunk's next expiry; a stale expiry event (its chunk already
    refreshed early by a client update) is skipped. Rows before ``warmup_s`` are discarded.
    """
    ring = ChordRing(n, seed=seed)
    domains = load_domains(n_domains)
    sim = LedgerSim(ring, domains, zipf_alpha=zipf_alpha, seed=seed)

    wrng = random.Random(seed ^ 0x1ED6E)      # ledger workload stream (independent, reproducible)
    horizon_ms = (warmup_s + duration_s) * 1000.0
    warmup_ms = warmup_s * 1000.0

    heap: list[tuple[float, int, str, str]] = []
    seq = itertools.count()
    rows: list[UpdateRecord] = []

    # 1. Warm-up seeding: commit every domain at t=0 (primary as proposer), schedule first expiry.
    #    These t=0 rows fall in the warm-up window and are discarded.
    for d in domains:
        sim.propose(sim.primary_of(d), d, "update", 0.0)
        heapq.heappush(heap, (sim.expiry[chunk_id(d)], next(seq), "expiry", d))

    # 2. Client-update stream (Zipf domains, random origins). --update-qps 0 -> pure TTL refresh.
    if update_qps > 0:
        interval = 1000.0 / update_qps
        t = 0.0
        while t < horizon_ms:
            heapq.heappush(heap, (t, next(seq), "update", sim.sample_domain(wrng)))
            t += interval

    # 3. Drain the heap in time order.
    while heap:
        t, _, kind, d = heapq.heappop(heap)
        if t >= horizon_ms:
            break
        cid = chunk_id(d)
        if kind == "expiry":
            if sim.expiry.get(cid, math.inf) > t + 1e-9:
                continue                                    # already refreshed early -> stale event
            rec = sim.propose(sim.primary_of(d), d, "ttl_refresh", t)   # only the primary refreshes
        else:
            rec = sim.propose(sim.random_origin(wrng), d, "update", t)
        heapq.heappush(heap, (sim.expiry[cid], next(seq), "expiry", d))
        if t >= warmup_ms:
            rows.append(rec)
    return sim, rows


# ---------------------------------------------------------------------------------------
# Stats + CSV output (mirrors query_sim).
# ---------------------------------------------------------------------------------------
def summarize(rows: list[UpdateRecord]) -> dict:
    updates = sum(1 for r in rows if r.action == "update")
    refreshes = sum(1 for r in rows if r.action == "ttl_refresh")
    committed = sum(1 for r in rows if r.outcome == "committed")
    aborted = sum(1 for r in rows if r.outcome == "aborted")
    rts = [r.round_trips for r in rows]
    msgs = [r.messages for r in rows]
    lat = sorted(r.latency_ms for r in rows)
    lat_refresh = sorted(r.latency_ms for r in rows if r.action == "ttl_refresh")
    return {
        "rows": len(rows),
        "updates": updates,
        "ttl_refreshes": refreshes,
        "committed": committed,
        "aborted": aborted,
        "rt_mean": statistics.fmean(rts) if rts else 0.0,
        "msg_mean": statistics.fmean(msgs) if msgs else 0.0,
        "entries_total": sum(r.entries_appended for r in rows),
        "ledger_len": max((r.ledger_len for r in rows), default=0),
        "p50_ms": _percentile(lat, 0.50),
        "p95_ms": _percentile(lat, 0.95),
        "p99_ms": _percentile(lat, 0.99),
        "p50_refresh_ms": _percentile(lat_refresh, 0.50),
        "p95_refresh_ms": _percentile(lat_refresh, 0.95),
    }


def write_per_update_csv(path: Path, rows: list[UpdateRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sim_time_ms", "domain", "proposer", "action", "outcome", "replicas", "hops",
                    "precommit_yes", "commit_ok", "round_trips", "messages", "entries_appended",
                    "ledger_len", "latency_ms"])
        for r in rows:
            w.writerow([f"{r.sim_time_ms:.3f}", r.domain, r.proposer, r.action, r.outcome,
                        r.replicas, r.hops, r.precommit_yes, r.commit_ok, r.round_trips,
                        r.messages, r.entries_appended, r.ledger_len, f"{r.latency_ms:.3f}"])


def append_summary_csv(path: Path, params: dict, s: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = ["n", "update_qps", "duration", "warmup", "seed", "domains", "zipf_alpha",
              "rows", "updates", "ttl_refreshes", "committed", "aborted",
              "rt_mean", "msg_mean", "entries_total", "ledger_len",
              "p50_ms", "p95_ms", "p99_ms", "p50_refresh_ms", "p95_refresh_ms"]
    new = not path.exists()
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(header)
        w.writerow([
            params["n"], f"{params['update_qps']:g}", params["duration_s"], params["warmup_s"],
            params["seed"], params["n_domains"], f"{params['zipf_alpha']:g}",
            s["rows"], s["updates"], s["ttl_refreshes"], s["committed"], s["aborted"],
            f"{s['rt_mean']:.3f}", f"{s['msg_mean']:.3f}", s["entries_total"], s["ledger_len"],
            f"{s['p50_ms']:.3f}", f"{s['p95_ms']:.3f}", f"{s['p99_ms']:.3f}",
            f"{s['p50_refresh_ms']:.3f}", f"{s['p95_refresh_ms']:.3f}",
        ])


def _print_summary(params: dict, s: dict) -> None:
    print(f"\nledger_sim workload — N={params['n']}, {params['update_qps']:g} update-qps, "
          f"{params['duration_s']}s (+{params['warmup_s']}s warm-up), seed {params['seed']}")
    tot = max(s["rows"], 1)
    print(f"  measured updates : {s['rows']}  "
          f"(update {s['updates']}, ttl_refresh {s['ttl_refreshes']})")
    print(f"  outcomes         : committed {s['committed']} ({100*s['committed']/tot:.1f}%)  "
          f"aborted {s['aborted']} ({100*s['aborted']/tot:.1f}%)")
    print(f"  messages/update  : mean {s['msg_mean']:.1f}  (round-trips {s['rt_mean']:.1f})")
    print(f"  ledger growth    : {s['entries_total']} entries this window, "
          f"cumulative {s['ledger_len']}")
    print(f"  latency (ms)     : p50 {s['p50_ms']:.1f}  p95 {s['p95_ms']:.1f}  p99 {s['p99_ms']:.1f}")
    print(f"  ttl_refresh (ms) : p50 {s['p50_refresh_ms']:.1f}  p95 {s['p95_refresh_ms']:.1f}")


# ---------------------------------------------------------------------------------------
# Self-test — invariants that must hold regardless of #29 calibration.
# ---------------------------------------------------------------------------------------
def _run_self_test() -> bool:
    ok = True
    ring = ChordRing(32, seed=DEFAULT_SEED)
    domains = load_domains(1000)

    # (1) Happy path: a fresh domain commits with all replicas voting yes and appending an entry.
    sim = LedgerSim(ring, domains, seed=DEFAULT_SEED)
    d0 = domains[123]
    origin = ring.ids[0]
    cid0 = chunk_id(d0)
    k = len(_replica_set(ring, ring.successor_of(cid0)))
    r_up = sim.propose(origin, d0, "update", 1000.0)
    if not (r_up.outcome == "committed" and r_up.precommit_yes == k
            and r_up.commit_ok == k and r_up.entries_appended == k):
        print(f"FAIL: happy path not fully committed: {r_up}")
        ok = False

    # (2) Message formula: round_trips = locate hops + get_succ_list + precommit k + commit k.
    exp_rt = r_up.hops + 1 + 2 * k
    if not (r_up.round_trips == exp_rt and r_up.messages == 2 * exp_rt):
        print(f"FAIL: message count {r_up.round_trips} rt / {r_up.messages} msg != {exp_rt} / {2*exp_rt}")
        ok = False

    # (3) Abort path (injected lock conflict): pre-commit fails, no entries, s abort RPCs charged.
    sim_ab = LedgerSim(ring, domains, seed=DEFAULT_SEED)
    d_ab = domains[200]
    cid_ab = chunk_id(d_ab)
    k_ab = len(_replica_set(ring, ring.successor_of(cid_ab)))
    sim_ab.pending[cid_ab] = "someone-else"                    # chunk already locked
    r_ab = sim_ab.propose(ring.ids[3], d_ab, "update", 5.0)
    if not (r_ab.outcome == "aborted" and r_ab.precommit_yes < (k_ab // 2 + 1)
            and r_ab.entries_appended == 0 and r_ab.round_trips == r_ab.hops + 1 + 2 * k_ab):
        print(f"FAIL: abort path wrong: {r_ab}")
        ok = False

    # (4) Latency composition reconstructs to the reported latency (committed, no fallback).
    rr = ring.route(origin, cid0)
    reps = _replica_set(ring, rr.responsible)
    recon = (_route_latency_ms(ring, rr) + _rpc_rtt_ms(ring, origin, rr.responsible)
             + max(_rpc_rtt_ms(ring, origin, r) for r in reps) + VOTE_PROC_MS
             + max(_rpc_rtt_ms(ring, origin, r) for r in reps))
    if abs(recon - r_up.latency_ms) > 1e-9:
        print(f"FAIL: latency composition {recon} != reported {r_up.latency_ms}")
        ok = False

    # (5) Ordering: a ttl_refresh costs exactly one fallback resolution more than an update.
    sim2 = LedgerSim(ring, domains, seed=DEFAULT_SEED)
    prim = sim2.primary_of(d0)
    r_u = sim2.propose(prim, d0, "update", 10.0)               # same proposer + domain
    sim3 = LedgerSim(ring, domains, seed=DEFAULT_SEED)
    r_r = sim3.propose(prim, d0, "ttl_refresh", 10.0)
    if not (abs(r_r.latency_ms - (r_u.latency_ms + FALLBACK_STEPS * FALLBACK_STEP_MS)) < 1e-9
            and r_u.latency_ms < r_r.latency_ms):
        print(f"FAIL: ttl_refresh latency {r_r.latency_ms} != update {r_u.latency_ms} + fallback")
        ok = False

    # (6) Ledger grows by commit_ok per committed update; cumulative length is monotonic.
    sim4 = LedgerSim(ring, domains, seed=DEFAULT_SEED)
    prev_len = 0
    mono = True
    for d in domains[:50]:
        rec = sim4.propose(ring.ids[1], d, "update", 0.0)
        if sim4.ledger_len != prev_len + rec.commit_ok or rec.ledger_len < prev_len:
            mono = False
        prev_len = sim4.ledger_len
    if not mono:
        print("FAIL: ledger_len not monotonic / not += commit_ok")
        ok = False

    # (7) TTL refresh proposer is always the chunk's primary; primary == successor_of(chunk_id).
    _sim, wrows = run_workload(n=32, update_qps=1.0, duration_s=4000, warmup_s=30, seed=DEFAULT_SEED)
    bad = 0
    for r in wrows:
        if r.action != "ttl_refresh":
            continue
        prim = ring.successor_of(chunk_id(r.domain))
        if r.proposer != f"node-{ring.pos[prim]}":
            bad += 1
    if wrows and sum(1 for r in wrows if r.action == "ttl_refresh") == 0:
        print("FAIL: no ttl_refresh rows produced by the workload (horizon too short?)")
        ok = False
    if bad:
        print(f"FAIL: {bad} ttl_refresh rows not proposed by the primary")
        ok = False

    # (8) Parallel per-phase latency (max) is a genuine lower bound on the sequential sum.
    par = max(_rpc_rtt_ms(ring, origin, r) for r in reps)
    seqsum = sum(_rpc_rtt_ms(ring, origin, r) for r in reps)
    if not (par <= seqsum):
        print(f"FAIL: parallel {par} not <= sequential {seqsum}")
        ok = False

    # (9) Placement identity: replica-set primary == successor_of(cid) (matches query_sim/storage).
    if _replica_set(ring, ring.successor_of(cid0))[0] != ring.successor_of(cid0):
        print("FAIL: replica-set primary != successor_of(cid)")
        ok = False

    # (10) SimPy smoke test — one full 2PC driven on a SimPy clock (the Phase 6 A2 layer).
    try:
        import simpy
    except ImportError:
        print("NOTE: simpy not installed — SimPy smoke test skipped (`pip install simpy`). "
              "Analytic latency/messages are unaffected.")
    else:
        env = simpy.Environment()
        holder: dict[str, float] = {}

        def _drive():
            # locate: replay the route hop-by-hop, then the get_succ_list RTT.
            rr2, route_lat = yield from lookup_latency(env, ring, origin, cid0)
            reps2 = _replica_set(ring, rr2.responsible)
            yield env.timeout(_rpc_rtt_ms(ring, origin, rr2.responsible))
            # phase 1: k parallel pre-commit round-trips.
            yield env.all_of([env.timeout(_rpc_rtt_ms(ring, origin, r)) for r in reps2])
            yield env.timeout(VOTE_PROC_MS)
            # phase 2: k parallel commit round-trips.
            yield env.all_of([env.timeout(_rpc_rtt_ms(ring, origin, r)) for r in reps2])
            holder["now"] = env.now

        env.process(_drive())
        env.run()
        if abs(holder.get("now", -1) - r_up.latency_ms) > 1e-6:
            print(f"FAIL: SimPy clock {holder.get('now')} != analytic latency {r_up.latency_ms}")
            ok = False
        else:
            print("SimPy smoke test OK (two-phase commit driven on a SimPy clock).")

    return ok


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Phase 5 (#27) ledger + update simulation.")
    p.add_argument("--n", type=int, default=DEFAULT_N, help="ring size (default 32)")
    p.add_argument("--update-qps", type=float, default=DEFAULT_UPDATE_QPS, dest="update_qps",
                   help="client-update rate; 0 = pure TTL refresh (default 1)")
    p.add_argument("--duration", type=int, default=DEFAULT_DURATION_S, dest="duration_s",
                   help="measurement seconds of sim time (default 7200)")
    p.add_argument("--warmup", type=int, default=DEFAULT_WARMUP_S, dest="warmup_s",
                   help="warm-up seconds, discarded (default 30)")
    p.add_argument("--domains", type=int, default=DEFAULT_DOMAINS, dest="n_domains",
                   help="number of Tranco domains (default 1000)")
    p.add_argument("--zipf", type=float, default=DEFAULT_ZIPF_ALPHA, dest="zipf_alpha",
                   help="Zipf popularity exponent (default 1.0)")
    p.add_argument("--seed", type=int, default=DEFAULT_SEED, help=f"RNG seed (default {DEFAULT_SEED})")
    p.add_argument("--no-self-test", action="store_true", help="skip the invariant self-test")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    ok = True
    if not args.no_self_test:
        print(f"ledger_sim self-test (seed {DEFAULT_SEED})")
        ok = _run_self_test()
        print("PASS" if ok else "FAILED")

    params = {
        "n": args.n, "update_qps": args.update_qps, "duration_s": args.duration_s,
        "warmup_s": args.warmup_s, "n_domains": args.n_domains,
        "zipf_alpha": args.zipf_alpha, "seed": args.seed,
    }
    _sim, rows = run_workload(
        n=args.n, update_qps=args.update_qps, duration_s=args.duration_s, warmup_s=args.warmup_s,
        n_domains=args.n_domains, zipf_alpha=args.zipf_alpha, seed=args.seed,
    )
    s = summarize(rows)
    _print_summary(params, s)

    per_update = _RESULTS_DIR / f"ledger_sim_N{args.n}.csv"
    write_per_update_csv(per_update, rows)
    append_summary_csv(_RESULTS_DIR / "ledger_sim_summary.csv", params, s)
    print(f"  wrote            : {per_update.relative_to(_HERE.parent)}  (+ summary row)")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
