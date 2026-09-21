# A2 — Throughput / saturation: methodology notes (issue #33, Phase 6, examiner point (iii))

Reproducible trail for the A2 experiment. Numbers live in
[`A2_throughput.csv`](A2_throughput.csv) and [`fig_A2_throughput.png`](fig_A2_throughput.png);
this file records *how* they were produced and the honest caveats (CLAUDE.md §2
"measure, don't assert" / "flag, don't hide").

## What A2 measures
End-to-end **success rate** and **p95 latency** (plus p50/p99 and achieved qps) of the resolver
ring at the frozen **N=32** emulation ceiling (`PARAMETERS.md` §1), as offered query load ramps
over **{10, 25, 50, 100, 150, 200} qps**, 30 s per level. The deliverable is a **throughput curve
with the saturation point marked** — the lowest offered qps whose mean success rate drops below
**95%** (issue #33's criterion) — contrasted with the Unbound baseline. A2 is **single-N** by
design: N=32 is the emulation ceiling, so multi-N throughput/per-node-load scaling is **A3**
(issue #34), not A2.

## Results (measured 2026-09-21, seed 20260919, 3 sweeps per level)
Headline success rate + p95, mean over 3 sweeps (full stats + run-to-run sd in
[`A2_throughput.csv`](A2_throughput.csv)):

| offered qps | achieved qps | success % (sd) | p95 (ms) | saturated |
|---|---|---|---|---|
| 10  | 10.0  | 100.0 (0.0) | 1423 | no  |
| 25  | 25.0  | 99.2 (0.2)  | 1104 | no  |
| 50  | 50.0  | 97.0 (1.9)  | 1032 | no  |
| 100 | 100.0 | **82.8 (2.5)** | 1066 | **yes** |
| 150 | 150.0 | 75.1 (2.1)  | 732  | yes |
| 200 | 200.0 | 75.6 (1.9)  | 630  | yes |

**Saturation point: 100 qps** — the first level below the 95% success line (the ring holds
≥97% through 50 qps, then collapses to ~83% at 100 qps and ~75% at 150–200 qps). Unbound over the
same hierarchy holds 100% to 200 qps and only 96.7% at 400 qps (`baseline_unbound.csv`), so the
decentralised ring saturates at roughly **¼ of Unbound's load** — the expected, defensible price
of Chord routing + majority-voted replica reads + store-back over netem.

**The generator was NOT the bottleneck (the key methodology check).** `achieved_qps` (derived from
the actual send-timestamp span, not `rows/duration`) tracks the offered rate to within 0.03 qps at
**every** level, including 200 qps — so the `--max-workers` sizing kept the 64-thread pool from
capping, and the failures above 50 qps are **genuine ring saturation** (queries timing out at the
node under load), not a load-generator artifact. This is what distinguishes A2's saturation from
the Unbound baseline's 400-qps stopping point (which *was* generator-limited, PARAMETERS.md §3).

**Why p95 (of successful queries) *falls* under saturation — an artifact, flagged not hidden.**
Percentiles are computed over **successful** rows only (the A1 / `summarise()` convention). Under
overload the ring keeps serving cheap **cache hits** (~1 ms) but the expensive **DHT/fallback**
queries increasingly time out and are excluded from the success set — so the surviving successful
latencies skew toward the cache-hit floor and p50/p95 *drop* (p50 collapses to ~1 ms by 50 qps).
The honest overload signal is therefore the **success rate**, not the latency-of-successful
percentiles; p95 is reported for completeness but must be read with this caveat. (A latency metric
that included the 5 s timeouts would instead rise — a different, equally valid lens; success rate
is the issue #33 criterion and the one the saturation point is drawn from.)

## Workload (frozen — `PARAMETERS.md`)
`--mode nodes`, **N=32**, six offered levels {10, 25, 50, 100, 150, 200} qps, **30 s measured per
level**, **30 s warm-up at 10 qps** (once per sweep), Zipf α=1.0 over 1000 Tranco domains, netem
two-tier 5/50 ms, seed 20260919, replication s=3, δ=2.0 s, PLOT_N=1024, DRG in-degree 2. **3 sweeps.**

## Methodology — one ring per sweep, ramp load (the one non-obvious choice)
A2 is a *saturation* experiment, so it holds the system fixed and varies offered load, rather than
rebuilding the ring per level. Each sweep:
1. brings up N=32 **once** via `testbed/run_experiment.sh --mode nodes ... --keep-up` (full
   bring-up: zones, `gen_nodes_compose.py`, health-gate, `netem.sh apply`, and a **30 s warm-up at
   10 qps** that converges the ring and populates the DHT — the throwaway 1 s measured run is
   ignored);
2. runs all six levels **ascending** against the same live ring, truncating each node's
   `queries.csv` and draining ~5 s between levels so a saturated level's backlog clears;
3. tears the ring down.

The whole sweep repeats **3×** for run-to-run std-dev (the plot's error bars).

Why not restart the ring per level (A1's pattern): a fresh ring's warm-up would run at that level's
qps, and warming an unconverged ring at a high qps starves `stabilize` of the event loop — the
**N=64 failure mode** (CLAUDE.md Phase 3). That would confound convergence with throughput. Warming
once at a low 10 qps and then ramping cleanly separates the two.

## The generator cap (flagged, not hidden)
`testbed/query_gen.py` is **open-loop** (it dispatches on a fixed 1/qps schedule, not waiting for
replies) but bounded by its worker pool (default **64**). Above ~64 concurrent queries — which the
higher levels reach under saturation, when queries approach the 5 s client timeout — the
**generator**, not the ring, becomes the bottleneck. This is the documented reason the Unbound
baseline was not pushed past 400 qps (`PARAMETERS.md` §3). A2 addresses it two ways:
- **`--max-workers` is sized per level** to `clamp(qps × 5 s timeout, 64, 1024)` so the pool never
  caps below the ring's own capacity.
- **`achieved_qps = rows / duration` is recorded per level** as the diagnostic. If `achieved_qps`
  tracks the offered rate but success falls < 95%, that is **genuine ring saturation** (queries
  time out / fail). If `achieved_qps` falls well below offered while success stays high, that flags
  a **residual generator cap** rather than ring saturation. Both are visible in the CSV and plot.

Note the metrics are robust to the cap regardless: the success-rate saturation criterion counts
timed-out/failed queries, which the ring produces under true saturation whether or not the
generator's sends are delayed.

## Unbound baseline overlay
`baseline_unbound.csv` is already a per-qps throughput sweep of the single Unbound resolver
(offered 10/50/100/200/400 qps). `a2_throughput.py` overlays its success + p95 curves as a
reference, so the figure shows directly how much earlier the decentralised ring saturates.

## Output schema — `A2_throughput.csv`
One row per offered level:
`offered_qps, achieved_qps, duration_s, warmup_s, nodes, seed, netem, sweeps, rows, ok,
success_rate_pct, success_sd, p50_ms, p95_ms, p99_ms, p95_sd, saturated`. Percentiles and
success are the **mean across the 3 sweeps** (over **successful** rows, matching the
`run_experiment.sh summarise()` convention); `success_sd` / `p95_sd` are the run-to-run
**standard deviations** (the plot's error bars); `saturated` is True for every level at/above the
saturation point.

## How to reproduce
```
bash experiments/run_a2.sh              # collect: 3 sweeps × 6 levels on N=32 (Docker Desktop)
python3 experiments/a2_throughput.py    # analyse -> A2_throughput.csv + fig_A2_throughput.png
```
Snapshots land under `results/a2/sweep<s>/q<Q>/client.csv` (git-ignored, seed-regenerable). Quick
smoke subset: `A2_QPS="10 50" A2_SWEEPS=1 bash experiments/run_a2.sh`.
