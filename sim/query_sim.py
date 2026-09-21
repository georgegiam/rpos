"""Phase 5 (#26, P5-2) — DNS query-path simulation.

Layers the resolver's full read path (Algorithm 2, ``node/query.py`` ``resolve_query``) on top of
the converged Chord ring from ``sim/chord_sim.py`` (#25). For each query it reproduces exactly what
the emulation resolver does:

    1. local cache (unexpired)                              -> "cache_hit"  (0 hops)
    2. DHT: route to the primary, fetch primary + s-1 replicas, majority vote -> "dht_hit"
    3. fallback: iterative resolution (root->TLD->auth) then store the answer back -> "fallback"

and emits per-query **hops** and **latency**, plus the realistic cache/dht_hit/fallback outcome
mixture, under a Zipf(alpha=1.0) workload over the same Tranco domain list the emulation used.

Design choices (locked for #26, stated openly per CLAUDE.md "flag, don't hide"):

* **Hops match the emulation ``queries.csv`` accounting exactly.** cache_hit = 0; dht_hit = the
  ``find_successor`` hops to the primary (``ChordRing.route`` — the replica fan-out RPCs are NOT
  counted, matching ``storage.get_chunk`` returning only the primary-lookup hops); fallback =
  route hops + ``FALLBACK_STEPS`` (the "+3" referral offset, ``total_hops = hops + steps`` in
  query.py). This is the source of the +offsets that pure-Chord ``chord_sim`` deliberately omits.

* **Calibrated against emulation (#29).** The per-leg delay weights are named module/instance
  constants that ``sim/calibrate.py`` tuned against N=8/N=32 emulation (``results/calibration.csv``):
  per-hop ``proc_delay_ms`` 1 -> 18 ms, ``FALLBACK_STEP_MS`` 50 -> 100 ms, and a routing hop is now
  charged as a full RTT (``chord_sim.hop_delay_ms``), keeping the measured 5/50 ms netem legs frozen.
  All latency metrics land within ~8% at both N. (Hops are topology, not delay: N=32 matches; N=8's
  median is one below emulation because the sim routes on a perfectly-converged ring — a documented
  finger-convergence idealisation, see calibration.csv / CLAUDE.md, not a calibration failure.)

* **Independent per-query latency (no node service-capacity contention).** Latency is a
  deterministic analytic sum of the legs a query traverses; throughput/saturation contention is
  Phase 6 A2. A SimPy smoke test proves the same query can be driven on a SimPy clock (the layer
  Phase 6 will use), mirroring how ``chord_sim`` keeps routing pure and only smoke-tests SimPy.

* **Cold-start warming.** The DHT starts empty; a warm-up window (results discarded) populates it
  via fallback+store-back, then the measurement window is logged — the emulation methodology
  (30 s warm-up, seed 20260919). First touch of a domain -> fallback + store; later touches ->
  dht_hit / cache_hit. Store visibility is applied in arrival order (a store is visible to later
  arrivals); exact completion-order visibility is a second-order effect left to #29.

Reuse: ``ChordRing`` / ``RouteResult`` / ``lookup_latency`` from ``sim/chord_sim.py`` (topology,
routing, per-hop delay) and ``chunk_id`` / ``RING_SIZE`` from ``node/ids.py`` (byte-identical
domain->chunk placement). ``S`` and ``FALLBACK_STEPS`` mirror ``node/storage.py`` and
``node/query.py``. ``node/chord.py`` is not imported (see chord_sim); its logic is reused via
``ChordRing``.

Run:  ``python -m sim.query_sim``            (self-test + default N=32 workload, writes CSVs)
      ``python -m sim.query_sim --n 32 --qps 10 --duration 30 --warmup 30``
"""
from __future__ import annotations

import argparse
import csv
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

from node.ids import RING_SIZE, chunk_id  # noqa: E402  (after sys.path)
from sim.chord_sim import (  # noqa: E402
    DEFAULT_PROC_DELAY_MS,
    DEFAULT_SEED,
    ChordRing,
    RouteResult,
    lookup_latency,
)

# ---- constants mirrored from the resolver (kept in sync with source) -------------------
S = 3                       # replication factor == node/storage.py S
FALLBACK_STEPS = 3          # iterative-resolution referral steps == node/query.py IterativeResolver.steps

# ---- per-leg delay weights — CALIBRATED in #29 (results/calibration.csv) ----------------
# A DHT RPC is a request+response round trip; we charge two one-way network legs plus one
# server-side processing delay (chord_sim.hop_delay_ms now does the same for routing hops).
# These two weights were calibrated with proc_delay against N=8/N=32 emulation (all latency
# metrics within ~8%); VOTE_PROC_MS stayed at its 0.5 ms default, FALLBACK_STEP_MS moved 50 -> 100.
VOTE_PROC_MS = 0.5          # majority-vote CPU after the replica reads return (calibrated #29)
FALLBACK_STEP_MS = 100.0    # per referral step to the upstream hierarchy (calibrated #29)

# ---- workload defaults (mirror results/PARAMETERS.md) ----------------------------------
TTL_LADDER_S = [300, 600, 900, 1800, 3600]   # discrete zone TTLs (testbed/dns/generate_zones.py)
DEFAULT_N = 32
DEFAULT_QPS = 10.0
DEFAULT_DURATION_S = 30
DEFAULT_WARMUP_S = 30
DEFAULT_DOMAINS = 1000
DEFAULT_ZIPF_ALPHA = 1.0

_HERE = Path(__file__).resolve().parent
_TRANCO_CSV = _HERE.parent / "testbed" / "dns" / "tranco" / "tranco_JZNVY_top100k.csv"
_RESULTS_DIR = _HERE / "results"


@dataclass
class QueryRecord:
    """One resolved query: what the emulation logs per row, plus latency and origin."""
    sim_time_ms: float      # arrival time on the sim clock
    domain: str
    origin: str             # "node-<sorted index>" (readable, reproducible)
    hops: int
    outcome: str            # cache_hit | dht_hit | fallback
    vote: str               # "cache" | "3/3" | "stored:3" | ...
    latency_ms: float


# ---------------------------------------------------------------------------------------
# Delay helpers (analytic; no SimPy). One-way network by region pair, from the ring.
# ---------------------------------------------------------------------------------------
def _net_ms(ring: ChordRing, a: int, b: int) -> float:
    """One-way network delay between two nodes (region-dependent)."""
    return ring.intra_ms if ring.region[a] == ring.region[b] else ring.inter_ms


def _rpc_rtt_ms(ring: ChordRing, a: int, b: int) -> float:
    """A request/response RPC round trip: two one-way network legs + one server-side proc."""
    return 2.0 * _net_ms(ring, a, b) + ring.proc_delay_ms


def _route_latency_ms(ring: ChordRing, rr: RouteResult) -> float:
    """Sum the one-way per-hop delay along a routed path (identical to lookup_latency's sum)."""
    lat = 0.0
    prev = rr.path[0]
    for nxt in rr.path[1:]:
        lat += ring.hop_delay_ms(prev, nxt)
        prev = nxt
    return lat


def _replica_set(ring: ChordRing, primary: int) -> list[int]:
    """[primary] + primary's successor list, truncated to S (mirrors storage.replica_set)."""
    nodes = [primary]
    for s in ring.succ_list[primary]:
        if s not in nodes:
            nodes.append(s)
        if len(nodes) >= S:
            break
    return nodes[:S]


# ---------------------------------------------------------------------------------------
# The query-path simulator.
# ---------------------------------------------------------------------------------------
class QuerySim:
    """Holds ring + DHT/cache state and resolves queries along Algorithm 2's three tiers."""

    def __init__(
        self,
        ring: ChordRing,
        domains: list[str],
        *,
        zipf_alpha: float = DEFAULT_ZIPF_ALPHA,
        seed: int = DEFAULT_SEED,
        fallback_steps: int = FALLBACK_STEPS,
        fallback_step_ms: float = FALLBACK_STEP_MS,
        vote_proc_ms: float = VOTE_PROC_MS,
    ) -> None:
        self.ring = ring
        self.domains = domains
        self.fallback_steps = fallback_steps
        self.fallback_step_ms = fallback_step_ms
        self.vote_proc_ms = vote_proc_ms

        # Cold start: empty DHT, empty per-node caches.
        self.dht_stored: set[int] = set()
        self.caches: dict[int, dict[str, float]] = {nid: {} for nid in ring.ids}

        # Per-domain TTL (seeded, deterministic) drawn from the zone TTL ladder.
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
        """Draw a domain by Zipf popularity (popular ranks dominate -> they get cached first)."""
        import bisect
        return self.domains[bisect.bisect_left(self._cum, rng.random())]

    def random_origin(self, rng: random.Random) -> int:
        """Query ingress node, uniform over the ring (queries spread across nodes)."""
        return rng.choice(self.ring.ids)

    # ---- the query path (analytic port of node/query.py resolve_query) ----
    def resolve(self, origin: int, domain: str, now_ms: float) -> QueryRecord:
        ring = self.ring
        cid = chunk_id(domain)
        origin_label = f"node-{ring.pos[origin]}"
        cache = self.caches[origin]

        # Tier 1: local cache (unexpired).
        exp = cache.get(domain)
        if exp is not None and exp > now_ms:
            return QueryRecord(now_ms, domain, origin_label, 0, "cache_hit", "cache",
                               ring.proc_delay_ms)

        # Tier 2: DHT read attempt — route to primary, learn replicas, read them (majority vote).
        rr = ring.route(origin, cid)
        primary = rr.responsible
        replicas = _replica_set(ring, primary)
        route_lat = _route_latency_ms(ring, rr)
        succ_rtt = _rpc_rtt_ms(ring, origin, primary)                 # get_succ_list RPC
        read_rtt = max((_rpc_rtt_ms(ring, origin, r) for r in replicas), default=0.0)  # parallel
        dht_read_lat = route_lat + succ_rtt + read_rtt
        k = len(replicas)
        ttl_ms = self.ttl_ms.get(domain, 1000.0 * TTL_LADDER_S[0])

        if cid in self.dht_stored:
            latency = dht_read_lat + self.vote_proc_ms
            cache[domain] = now_ms + ttl_ms
            return QueryRecord(now_ms, domain, origin_label, rr.hops, "dht_hit",
                               f"{k}/{k}", latency)

        # Tier 3: fallback — the DHT read above returned nothing, so resolve iteratively and
        # store the answer back. total_hops = route hops + referral steps (node/query.py).
        fb_lat = self.fallback_steps * self.fallback_step_ms
        write_rtt = max((_rpc_rtt_ms(ring, origin, r) for r in replicas), default=0.0)  # parallel
        store_lat = route_lat + succ_rtt + write_rtt          # store_chunk re-routes + writes
        latency = dht_read_lat + fb_lat + store_lat
        self.dht_stored.add(cid)                              # chunk now lives on its replica set
        cache[domain] = now_ms + ttl_ms
        return QueryRecord(now_ms, domain, origin_label, rr.hops + self.fallback_steps,
                           "fallback", f"stored:{k}", latency)


# ---------------------------------------------------------------------------------------
# Domain list — reuse the emulation's Tranco snapshot in rank order (falls back to synth).
# ---------------------------------------------------------------------------------------
def load_domains(count: int, tranco_csv: Path = _TRANCO_CSV) -> list[str]:
    """First ``count`` domains in Tranco rank order (same set the testbed zones use).

    Reproducible: rank order is fixed. If the vendored snapshot is absent, synthesize a
    deterministic list — only the string feeds chunk_id, so placement is still reproducible.
    """
    if tranco_csv.exists():
        out: list[str] = []
        with open(tranco_csv, newline="") as f:
            for row in csv.reader(f):
                if len(row) >= 2 and row[1]:
                    out.append(row[1].strip().lower())
                if len(out) >= count:
                    break
        if len(out) >= count:
            return out[:count]
    return [f"domain{i}.example" for i in range(count)]


# ---------------------------------------------------------------------------------------
# Workload runner (open-loop, fixed-rate, deterministic given the seed).
# ---------------------------------------------------------------------------------------
def run_workload(
    *,
    n: int = DEFAULT_N,
    qps: float = DEFAULT_QPS,
    duration_s: int = DEFAULT_DURATION_S,
    warmup_s: int = DEFAULT_WARMUP_S,
    n_domains: int = DEFAULT_DOMAINS,
    zipf_alpha: float = DEFAULT_ZIPF_ALPHA,
    seed: int = DEFAULT_SEED,
    proc_delay_ms: float = DEFAULT_PROC_DELAY_MS,
    vote_proc_ms: float = VOTE_PROC_MS,
    fallback_step_ms: float = FALLBACK_STEP_MS,
) -> tuple[QuerySim, list[QueryRecord]]:
    """Run the query workload; return (sim, measurement-window records).

    The three processing-delay levers (``proc_delay_ms`` per-hop CPU, ``vote_proc_ms``
    majority-vote CPU, ``fallback_step_ms`` per referral step) are injectable so ``sim/calibrate.py``
    (#29) can sweep them against N=8/N=32 emulation. The measured netem network delays
    (``intra_ms``/``inter_ms``) are NOT levers — they stay at the frozen 5/50 ms.
    """
    ring = ChordRing(n, seed=seed, proc_delay_ms=proc_delay_ms)
    domains = load_domains(n_domains)
    sim = QuerySim(ring, domains, zipf_alpha=zipf_alpha, seed=seed,
                   vote_proc_ms=vote_proc_ms, fallback_step_ms=fallback_step_ms)

    wrng = random.Random(seed ^ 0xA5A5)
    total_s = warmup_s + duration_s
    n_queries = int(round(qps * total_s))
    interval_ms = 1000.0 / qps
    warmup_ms = warmup_s * 1000.0

    rows: list[QueryRecord] = []
    for k in range(n_queries):
        t_ms = k * interval_ms
        domain = sim.sample_domain(wrng)
        origin = sim.random_origin(wrng)
        rec = sim.resolve(origin, domain, t_ms)
        if t_ms >= warmup_ms:                 # discard warm-up window (emulation methodology)
            rows.append(rec)
    return sim, rows


# ---------------------------------------------------------------------------------------
# Stats + CSV output.
# ---------------------------------------------------------------------------------------
def _percentile(sorted_vals: list[float], p: float) -> float:
    """Linear-interpolated percentile (p in [0,1]) of an already-sorted list."""
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * p
    lo = int(math.floor(k))
    hi = min(lo + 1, len(sorted_vals) - 1)
    if lo == hi:
        return sorted_vals[lo]
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def summarize(rows: list[QueryRecord]) -> dict:
    counts = {"cache_hit": 0, "dht_hit": 0, "fallback": 0}
    for r in rows:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
    hops = [r.hops for r in rows]
    lat = sorted(r.latency_ms for r in rows)
    return {
        "rows": len(rows),
        "cache_hit": counts["cache_hit"],
        "dht_hit": counts["dht_hit"],
        "fallback": counts["fallback"],
        "hop_median": statistics.median(hops) if hops else 0,
        "hop_mean": statistics.fmean(hops) if hops else 0.0,
        "p50_ms": _percentile(lat, 0.50),
        "p95_ms": _percentile(lat, 0.95),
        "p99_ms": _percentile(lat, 0.99),
    }


def write_per_query_csv(path: Path, rows: list[QueryRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sim_time_ms", "domain", "origin", "hops", "outcome", "vote", "latency_ms"])
        for r in rows:
            w.writerow([f"{r.sim_time_ms:.3f}", r.domain, r.origin, r.hops,
                        r.outcome, r.vote, f"{r.latency_ms:.3f}"])


def append_summary_csv(path: Path, params: dict, s: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = ["n", "qps", "duration", "warmup", "seed", "domains", "zipf_alpha",
              "rows", "cache_hit", "dht_hit", "fallback",
              "hop_median", "hop_mean", "p50_ms", "p95_ms", "p99_ms"]
    new = not path.exists()
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(header)
        w.writerow([
            params["n"], f"{params['qps']:g}", params["duration_s"], params["warmup_s"],
            params["seed"], params["n_domains"], f"{params['zipf_alpha']:g}",
            s["rows"], s["cache_hit"], s["dht_hit"], s["fallback"],
            f"{s['hop_median']:g}", f"{s['hop_mean']:.3f}",
            f"{s['p50_ms']:.3f}", f"{s['p95_ms']:.3f}", f"{s['p99_ms']:.3f}",
        ])


def _print_summary(params: dict, s: dict) -> None:
    print(f"\nquery_sim workload — N={params['n']}, {params['qps']:g} qps, "
          f"{params['duration_s']}s (+{params['warmup_s']}s warm-up), seed {params['seed']}")
    tot = max(s["rows"], 1)
    print(f"  measured queries : {s['rows']}")
    print(f"  outcomes         : cache_hit {s['cache_hit']} ({100*s['cache_hit']/tot:.1f}%)  "
          f"dht_hit {s['dht_hit']} ({100*s['dht_hit']/tot:.1f}%)  "
          f"fallback {s['fallback']} ({100*s['fallback']/tot:.1f}%)")
    print(f"  hops             : median {s['hop_median']:g}, mean {s['hop_mean']:.2f}")
    print(f"  latency (ms)     : p50 {s['p50_ms']:.1f}  p95 {s['p95_ms']:.1f}  p99 {s['p99_ms']:.1f}")


# ---------------------------------------------------------------------------------------
# Self-test — invariants that must hold regardless of #29 calibration.
# ---------------------------------------------------------------------------------------
def _run_self_test() -> bool:
    ok = True
    ring = ChordRing(32, seed=DEFAULT_SEED)
    domains = load_domains(1000)
    origin = ring.ids[0]

    # (1) A fresh (unstored) domain resolves as fallback with hops = route hops + FALLBACK_STEPS.
    sim = QuerySim(ring, domains, seed=DEFAULT_SEED)
    d0 = domains[123]
    base_hops = ring.route(origin, chunk_id(d0)).hops
    r_fb = sim.resolve(origin, d0, 0.0)
    if not (r_fb.outcome == "fallback" and r_fb.hops == base_hops + FALLBACK_STEPS):
        print(f"FAIL: fallback hops {r_fb.hops} != route {base_hops} + {FALLBACK_STEPS}")
        ok = False

    # (2) After the fallback stored it, the SAME domain from a DIFFERENT origin is a dht_hit at
    #     that origin's route hops (replica fan-out is not counted in hops).
    origin2 = ring.ids[7]
    exp_hops = ring.route(origin2, chunk_id(d0)).hops
    r_dht = sim.resolve(origin2, d0, 1.0)
    if not (r_dht.outcome == "dht_hit" and r_dht.hops == exp_hops):
        print(f"FAIL: dht_hit hops {r_dht.hops} != route {exp_hops}")
        ok = False

    # (3) Repeating from the same origin within TTL is a cache_hit with 0 hops.
    r_cache = sim.resolve(origin2, d0, 2.0)
    if not (r_cache.outcome == "cache_hit" and r_cache.hops == 0
            and abs(r_cache.latency_ms - ring.proc_delay_ms) < 1e-9):
        print(f"FAIL: cache_hit not 0 hops / proc-delay latency: {r_cache}")
        ok = False

    # (4) Latency ordering: cache_hit < dht_hit < fallback (the three tiers cost strictly more).
    if not (r_cache.latency_ms < r_dht.latency_ms < r_fb.latency_ms):
        print(f"FAIL: latency ordering cache {r_cache.latency_ms} "
              f"dht {r_dht.latency_ms} fallback {r_fb.latency_ms}")
        ok = False

    # (5) Zipf sampler is skewed: rank-1 domain drawn far more than the uniform 1/D expectation.
    zrng = random.Random(DEFAULT_SEED)
    trials = 20000
    top = sum(1 for _ in range(trials) if sim.sample_domain(zrng) == domains[0])
    if top <= trials / len(domains) * 5:
        print(f"FAIL: Zipf not skewed — top domain {top}/{trials} (uniform would be "
              f"{trials/len(domains):.1f})")
        ok = False

    # (6) SimPy smoke test — the workload can be driven on a SimPy clock (Phase 6 A2 layer).
    #     Each query becomes a process that waits its analytic latency; assert the clock agrees.
    try:
        import simpy
    except ImportError:
        print("NOTE: simpy not installed — SimPy smoke test skipped (`pip install simpy`). "
              "Analytic latency/hops are unaffected.")
    else:
        env = simpy.Environment()
        sample = [r_dht, r_fb]
        done: list[float] = []

        def _proc(rec):
            yield env.timeout(rec.latency_ms)
            done.append(env.now)

        for rec in sample:
            env.process(_proc(rec))
        env.run()
        if not (abs(env.now - max(r.latency_ms for r in sample)) < 1e-6
                and len(done) == len(sample)):
            print(f"FAIL: SimPy clock {env.now} != max latency; done={done}")
            ok = False
        else:
            # And a route replayed hop-by-hop via chord_sim.lookup_latency matches the analytic sum.
            env2 = simpy.Environment()
            holder: dict[str, tuple] = {}

            def _drive():
                holder["res"] = yield from lookup_latency(env2, ring, origin, chunk_id(d0))

            env2.process(_drive())
            env2.run()
            _rr, replay_lat = holder["res"]
            if abs(replay_lat - _route_latency_ms(ring, _rr)) > 1e-6:
                print(f"FAIL: SimPy route replay {replay_lat} != analytic {_route_latency_ms(ring, _rr)}")
                ok = False
            else:
                print("SimPy smoke test OK (query processes + hop-by-hop route replay).")

    return ok


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Phase 5 (#26) DNS query-path simulation.")
    p.add_argument("--n", type=int, default=DEFAULT_N, help="ring size (default 32)")
    p.add_argument("--qps", type=float, default=DEFAULT_QPS, help="offered query rate (default 10)")
    p.add_argument("--duration", type=int, default=DEFAULT_DURATION_S, dest="duration_s",
                   help="measurement seconds (default 30)")
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
        print(f"query_sim self-test (seed {DEFAULT_SEED})")
        ok = _run_self_test()
        print("PASS" if ok else "FAILED")

    params = {
        "n": args.n, "qps": args.qps, "duration_s": args.duration_s,
        "warmup_s": args.warmup_s, "n_domains": args.n_domains,
        "zipf_alpha": args.zipf_alpha, "seed": args.seed,
    }
    _sim, rows = run_workload(
        n=args.n, qps=args.qps, duration_s=args.duration_s, warmup_s=args.warmup_s,
        n_domains=args.n_domains, zipf_alpha=args.zipf_alpha, seed=args.seed,
    )
    s = summarize(rows)
    _print_summary(params, s)

    per_query = _RESULTS_DIR / f"query_sim_N{args.n}.csv"
    write_per_query_csv(per_query, rows)
    append_summary_csv(_RESULTS_DIR / "query_sim_summary.csv", params, s)
    print(f"  wrote            : {per_query.relative_to(_HERE.parent)}  (+ summary row)")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
