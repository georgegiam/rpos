# A1 — Latency vs N: methodology notes (issue #32, Phase 6, examiner point (iii))

Reproducible trail for the A1 experiment. Numbers live in
[`A1_latency_vs_N.csv`](A1_latency_vs_N.csv) and [`fig_A1_latency_vs_N.png`](fig_A1_latency_vs_N.png);
this file records *how* they were produced and the honest caveats (CLAUDE.md §2
"measure, don't assert" / "flag, don't hide").

## Results (measured 2026-09-21, seed 20260919, 3 runs per N)
Headline p50 (mean over 3 runs; full p50/p95/p99 + run-to-run sd in the CSV):

| N | all p50 | cache_hit p50 | dht_hit p50 | fallback p50 | success |
|---|---|---|---|---|---|
| 4  | 4.8 ms  | 3.2 ms | 319 ms | 497 ms  | 99.9% |
| 8  | 271 ms  | 2.8 ms | 347 ms | 681 ms  | 100%  |
| 16 | 335 ms  | 2.4 ms | 355 ms | 723 ms  | 99.9% |
| 32 | 511 ms  | 1.3 ms | 487 ms | 1022 ms | 99.2% |

Unbound (N-independent flat band): p50 **3.5** / p95 **132.6** / p99 **214.3** ms.

**Interpretation.** Cache hits are essentially local (≈1–3 ms, flat in N — no ring traffic) and
actually *beat* Unbound's warm p50. DHT hits and fallbacks pay Chord routing, so both grow with N
(dht_hit 319→487 ms, fallback 497→1022 ms as N goes 4→32), consistent with the ≈½·log₂N hop growth
(PARAMETERS.md §2). The **overall** median is governed by the outcome mix, not just per-outcome
cost: at N=4 half the queries are cache hits (share 51%), so the overall p50 is a few ms; as N
grows the cache-hit share falls (51%→42%→33%→25%) and the median migrates toward the DHT/fallback
cost, hence the overall p50 climb. The resolver's DHT/fallback tail is ~3–8× Unbound's — the
expected price of decentralised routing + majority-voted replica reads + store-back over netem —
while its cache path is competitive. Success stays ≥99.2% across all N (N=32 sits at the emulation
ceiling; its p99 is the noisiest metric, sd reported not hidden).

**Sanity gates (all pass).** Overall p50/p95 reproduce the pre-existing `experiments.csv` nodes-mode
rows at N=8 (~249–290 / ~887–895) and N=32 (~492–525 / ~1425–1544) within run variance, confirming
the join preserves the exact client latency. Join match-quality 99.9–100%. Unbound band ≈ frozen
baseline. Sim cross-check (`sim/query_sim.py`): overall p50 within 2.3% (N=8) / 7.6% (N=32); the
per-outcome split is looser (dht/fallback ~20–34%, non-gating) and the cache-hit relative error is
large *only* because emulation cache ≈1 ms vs the sim's 18 ms proc floor — a negligible absolute gap.

## What A1 measures
End-to-end DNS query latency (p50/p95/p99) of the resolver ring as a function of ring size
**N = 4, 8, 16, 32** — all within the frozen **N=32 emulation ceiling** (`PARAMETERS.md` §1) — split
by the three resolver outcomes (**cache_hit / dht_hit / fallback**), vs the Unbound baseline.

## Workload (frozen — `PARAMETERS.md`)
`--mode nodes`, **10 qps offered, 30 s measured, 30 s warm-up**, Zipf α=1.0 over 1000 Tranco
domains, netem two-tier 5/50 ms, seed 20260919, replication s=3, δ=2.0 s, PLOT_N=1024, DRG δ=2.
**3 runs per N.** 10 qps is the *unsaturated* latency load — throughput/saturation is A2, not A1.

## How to reproduce
```
bash experiments/run_a1.sh          # collect: 4 N × 3 runs (nodes) + 3 runs (Unbound)
python3 experiments/a1_latency_vs_n.py   # analyse -> A1_latency_vs_N.csv + fig_A1_latency_vs_N.png
```
Requires Docker Desktop. Snapshots land under `results/a1/N<n>/run<r>/` (client + node logs) and
`results/a1/unbound/run<r>/`.

## The latency↔outcome join (the one non-obvious step)
Emulation logs the two quantities A1 needs in **separate files with no capture-time join key**:
- **client-side** `results/exp_*_nodes.csv`: `timestamp,domain,resolver_used,latency_ms,success`
  — the exact client-observed RTT (the same metric as the Unbound baseline), but **no outcome**.
- **node-side** `ring/<j>/queries.csv`: `timestamp,domain,hops,outcome,vote_result`
  — the cache/dht/fallback **outcome** + hops, but **no latency**.

`a1_latency_vs_n.py` keeps the **client RTT** and attributes it an outcome by pairing, **within each
`(serving node, domain)` bucket**, the client rows and that node's log rows in time order.
`resolver_used = node-<hex>` maps to ring index `j` because node `j` is built from `_pk_for(j)`
(byte-identical in `node/run_node.py` and `testbed/query_gen.py`) and its container is bind-mounted
to `ring/<j>/`. At 10 qps per-node concurrency is low, so the pairing is near-exact.

**Why this join and not the alternatives** (user-approved decision):
- *vs. node-side latency instrumentation*: that would introduce a **second, non-comparable** latency
  (server-side, missing the client↔node UDP leg). The join keeps one latency definition — the
  client RTT — so the outcome split and the Unbound comparison are the same metric.
- *vs. taking the split from the simulator*: A1 is an **emulation** experiment ("run mode=nodes").
  The sim is used only as an independent **cross-check** (below), not as the headline.

**Match quality is reported, not hidden.** The analysis prints, per N, the fraction of client rows
that received a node outcome. Client rows with no matching node row (e.g. a query that timed out
before the node logged) are labelled `unmatched`: they are still counted in the **overall** ("all")
percentiles but excluded from the per-outcome split, so the per-outcome shares need not sum to 100%.

## Unbound baseline = flat reference band
Unbound is a single recursive resolver with **no notion of N** (host mode ignores node count and
drives one Unbound instance over the same hierarchy + netem). So it is collected **once, 3 runs**,
and drawn as a flat band (mean ± run-to-run sd) across every N. In `A1_latency_vs_N.csv` the Unbound
row is repeated per N so the table is self-contained at each N. Expected reference (`PARAMETERS.md`
§3, 10 qps): p50 ≈ 3.5 / p95 ≈ 132.9 / p99 ≈ 214.9 ms.

## Cross-check against the calibrated simulator
`a1_latency_vs_n.py` runs `sim/query_sim.py`'s `run_workload` at N=8/N=32 and prints the per-outcome
p50 deltas emulation-vs-sim. This is **non-gating** and documented: the sim was calibrated to pooled
p50/p95 within ≤8% (`calibration.csv`), and the per-outcome split is expected to track within a
similar band. Large deltas would flag a join or workload discrepancy to investigate, not an
automatic failure.

## Output schema — `A1_latency_vs_N.csv`
Tidy long format, one row per `(n, resolver, outcome)`:
`n, resolver{rpos|unbound}, outcome{all|cache_hit|dht_hit|fallback}, runs, n_rows, share_pct,
success_pct, p50_ms, p95_ms, p99_ms, p50_sd, p95_sd, p99_sd`. Percentiles are the **mean across the
3 runs**; `*_sd` is the run-to-run **standard deviation** (the plot's error bars). Percentiles are
computed over **successful** rows (matches the `run_experiment.sh summarise()` convention);
`success_pct` is overall for `all`, and per-outcome for the outcome rows (cache/dht ≈ 100 %,
fallback may be lower). `share_pct` is the outcome's share of queries (the outcome mix).
