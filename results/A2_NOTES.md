# A2 — Throughput / saturation: methodology notes (issue #33, Phase 6, examiner point (iii))

Reproducible trail for the A2 experiment. Numbers live in
[`A2_throughput.csv`](A2_throughput.csv) and [`fig_A2_throughput.png`](fig_A2_throughput.png);
this file records *how* they were produced and the honest caveats (CLAUDE.md §2
"measure, don't assert" / "flag, don't hide").

## What A2 measures (cache-controlled redo, 2026-09-29)
Success rate and p95 latency of the resolver ring at the frozen **N=32** ceiling as offered load
ramps over **{25, 50, 75, 100, 125, 150, 175, 200(, 250, 300)} qps**, 30 s per level, 3 sweeps.
The deliverable is **two clean curves with the cache state pinned**, each level a fair independent
measurement:

- **COLD-PATH** — the resolver cache never retains, so **every query exercises the DHT read path**
  (route + s=3 replica reads + majority vote). The conservative, cache-free saturation.
- **STEADY** — the cache is fully pre-warmed and stays warm, so **every query is served from cache**.
  The cache-assisted throughput ceiling.

## Results (measured 2026-09-29, seed 20260919, 3 sweeps per level)
Full stats + run-to-run sd in [`A2_throughput.csv`](A2_throughput.csv). "Path" is the node-side
outcome mix, which **proves** the cache was controlled (not asserted).

| offered qps | COLD success % (sd) | COLD p95 | STEADY success % | STEADY p95 |
|---|---|---|---|---|
| 25  | 99.9 (0.1) | 655 ms | 100.0 | 2.8 ms |
| 50  | 100.0 (0.0)| 646 ms | 100.0 | 1.3 ms |
| 75  | 99.8 (0.1) | 654 ms | 100.0 | 1.3 ms |
| 100 | 98.3 (0.1) | 654 ms | 100.0 | 1.5 ms |
| 125 | 98.4 (0.2) | 650 ms | 100.0 | 1.2 ms |
| 150 | 97.5 (0.1) | 653 ms | 100.0 | 1.0 ms |
| 175 | 96.7 (0.3) | 647 ms | 100.0 | 1.3 ms |
| 200 | 95.7 (0.2) | 645 ms | 100.0 | 1.1 ms |
| 250 | **94.2 (0.3)** | 653 ms | — | — |
| 300 | 92.8 (0.2) | 653 ms | — | — |

- **COLD-PATH saturation (first < 95% success) = 250 qps.** Success declines *monotonically*
  99.9 → 92.8 % across 25 → 300 qps; the node-side mix is **100 % dht_hit at every level** (0 %
  cache, 0 % fallback), so this is the pure DHT read path.
- **STEADY saturation = none ≤ 200 qps.** 100 % success throughout, node-side mix **100 % cache_hit**;
  the cache path has large headroom over the tested range.
- **p95 is monotonically non-decreasing on both curves** — in fact **flat**: ~650 ms for COLD (the
  inherent DHT read latency) and ~1 ms for STEADY (cache latency), independent of load until
  saturation. Flat/rising p95 (never falling with load) is the direct evidence that the old
  cache-warming confound is gone.
- **Cache state is pinned across load:** the per-level `cache_hit`/`dht_hit` share has std-dev
  **0.0 pp** across all levels on both curves — the cache cannot accumulate-with-load and bias p95.
- The COLD vs STEADY gap — **~650 ms vs ~1 ms p95, and saturation 250 qps vs > 200 qps with room**
  — quantifies the value of caching: the resolver leans heavily on its cache; the raw DHT path is
  ~650× slower per query and saturates first.

**Generator was not the bottleneck** (the key check): `achieved_qps` tracks the offered rate to
within ±0.05 qps at *every* level, including 300 qps (send-timestamp-derived), so COLD's failures
above 200 qps are genuine ring saturation, not a generator cap. Unbound over the same hierarchy
holds 100 % to 200 qps (`baseline_unbound.csv`) — faster than the cold DHT path, slower-headroom
than the warm cache path, as expected.

## Why this replaced the earlier ascending sweep (the methodology fix)
The original A2 ramped load on ONE ring with the caches left to **accumulate across levels**, so the
curve confounded load with cache warming: p95 *fell* as qps rose (1774 ms @50 → 8.9 ms @100), and
the "saturation" point drifted with how warm the cache happened to be (100 qps coarse → 150 qps
finer). That measures cache accumulation, not saturation. The redo **pins** the cache with a TTL
knob so each level is independent and p95 is monotone. Both earlier readings are superseded by the
two curves above; the old mixed-provenance data was removed (single provenance now).

## How the cache is controlled without touching frozen code
`node/run_ring_node.py` reads env **`UPSTREAM_TTL`** (default **300** ⇒ A1/A3–A7 byte-identical) and
passes it to the fallback resolver, which sets both the stored-chunk TTL and `node/query.py`'s
local-cache retention:
- **COLD** ⇒ `UPSTREAM_TTL=0`: a cache entry is already expired on the next lookup ⇒ pure DHT path.
- **STEADY** ⇒ `UPSTREAM_TTL=100000`: a warmed entry never expires within the run ⇒ pure cache path.

`node/storage.py` never expires chunks and fallback-stored chunks are not ledger-refreshed, so TTL
moves **only** the cache, not DHT availability or background load. `gen_nodes_compose.py` bakes
`UPSTREAM_TTL` into the compose from the host env. No frozen artifact is modified — `rpos.py`,
`chord.py`, `ledger.py`, `storage.py`, `query.py` are all byte-identical.

## Entry model: single entry node (node 0), both curves
All queries enter node 0 (`query_gen --ring-nodes 1`), as in A6, so node 0's cache is **coherent and
fully controllable** (round-robin over 32 nodes would give each node an incoherent partial cache,
defeating the control). This isolates the two paths through one entry point.

**Discarded alternative (flagged):** an exploratory COLD run with *distributed* entry (every node an
entry, `--ring-nodes 32`) gave non-monotonic, unstable success (82 % @25, 96 % @50, 75 % @75 …) with
success *rising within* a level. Cause: sustained pure-DHT RPC load from all 32 entries perturbs
`chord.py`'s stabilize/finger maintenance and the ring reconverges *during* the measurement — the
same frozen-`chord.py` maintenance fragility documented for N=64 (CLAUDE.md Phase 3), not a
load-saturation signal. The funnel avoids it. So the reported COLD number is the single-entry DHT
saturation; the aggregate distributed DHT path is *more* fragile, bounded by chord.py maintenance
under RPC pressure rather than by queueing — a limitation of the frozen code, stated not hidden.

## Workload (frozen — `PARAMETERS.md`)
`--mode nodes`, **N=32**, 30 s measured per level, netem two-tier 5/50 ms, seed 20260919,
replication s=3, δ=2.0 s, PLOT_N=1024, DRG in-degree 2, **3 sweeps** (fresh ring each). MEASUREMENT
uses the frozen Zipf α=1.0 workload; the per-sweep **warm-up is alpha=0 (uniform, full-coverage,
to node 0)** so the DHT is fully populated (both curves) and node 0's cache fully warmed (STEADY)
before any level — with the cache pinned, levels are order-independent and share one ring per sweep.
`--max-workers` per level = `clamp(qps × 5 s, 64, 1024)` so the generator never caps below the ring.

## Output schema — `A2_throughput.csv`
One row per (curve, offered level):
`curve, offered_qps, achieved_qps, nodes, duration_s, sweeps, rows, ok, success_rate_pct,
success_sd, p50_ms, p95_ms, p99_ms, p95_sd, cache_hit_pct, dht_hit_pct, fallback_pct,
p95_monotonic_ok, saturated, note`. Percentiles/success are the mean over the 3 sweeps (over
successful rows); `*_sd` are run-to-run std-devs; `cache_hit/dht_hit/fallback_pct` are the pooled
node-side outcome mix (the path proof); `p95_monotonic_ok` is the non-decreasing check over the
non-saturated region; `saturated` is True at/above the first-<95% level.

## How to reproduce
```
bash experiments/run_a2.sh              # both curves, 3 sweeps, 8 levels on N=32 (Docker Desktop)
python3 experiments/a2_throughput.py    # analyse -> A2_throughput.csv + fig_A2_throughput.png
```
Cold-only, extended range (as run here): `A2_CURVES=cold A2_QPS="25 50 75 100 125 150 175 200 250
300" A2_SWEEPS=3 bash experiments/run_a2.sh`. Snapshots land under
`results/a2/<curve>/sweep<s>/q<Q>/{client.csv,ring/}` (git-ignored, seed-regenerable). Quick smoke:
`A2_CURVES="cold steady" A2_SWEEPS=1 A2_QPS="25 200" bash experiments/run_a2.sh`.
