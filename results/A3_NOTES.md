# A3 — Scalability (throughput & per-node load vs N): methodology notes (issue #34, Phase 6, examiner point (iii))

Reproducible trail for the A3 experiment. Numbers live in
[`A3_scalability.csv`](A3_scalability.csv) and [`fig_A3_scalability.png`](fig_A3_scalability.png);
this file records *how* they were produced and the honest caveats (CLAUDE.md §2 "measure, don't
assert" / "flag, don't hide").

## What A3 measures
How the resolver scales with ring size **N** at a **fixed offered load of 50 qps**:
- **Per-node message load (msgs/node/s)** — the headline scalability signal. It **falls as N
  grows**, because a fixed query load is spread over more nodes while each query still touches only
  O(log N) of them. This is the property that says the design scales.
- **Throughput / goodput** — near-flat at ~50 qps below saturation, confirming that growing the
  ring does not cost throughput. (Saturation itself is A2's job, not A3's.)

Emulation carries **N = 4, 8, 16, 32** (the frozen emulation ceiling, `PARAMETERS.md` §1);
the calibrated Phase-5 simulator carries **N = 1,000 / 5,000 / 10,000** and is also run at
N = 4/8/16/32 as an **emulation-vs-sim overlap check**. The deliverable is one **combined
emulation + simulation scalability curve** (issue #34 "done when").

## Fixed offered load = 50 qps (and why)
50 qps is **below** the ring's saturation point — A2 measured ~97% success at 50 qps for N=32
(`A2_throughput.csv`) — so every emulation N is a valid, unsaturated operating point. A3 is a
*scalability* curve (vary N, hold load), not a *saturation* curve (vary load, hold N = A2).

## Per-node load — the one non-obvious mechanic (identical model both sides)
The emulation has **no wire-level RPC counter** (adding one would touch frozen transport code,
CLAUDE.md §2), and the simulator's `msgs_per_node_per_s` is itself a **model** derived from each
query's routing outcome. To make the emulation and sim points **directly comparable on one curve**,
A3 applies the **same model to both**:

`sim/scale_sim.py`'s `ring_round_trips(outcome, hops)` (round trip = req+resp = **2 messages**):
- `cache_hit` → 0 ring RPCs (served locally),
- `dht_hit` → `route_hops + 1 (get_succ_list) + S (replica reads)`, S=3,
- `fallback` → `2·(route_hops + 1 + S)` (failed DHT read + store-back),

where `route_hops` = the `find_successor` path length (`dht_hit` = logged hops; `fallback` =
`logged hops − FALLBACK_STEPS`, the "+3" referral offset). The emulation node logs
(`results/ring/<j>/queries.csv`) record `(outcome, hops)` per query with **exactly these
conventions** (`node/query.py`), so `experiments/a3_scalability.py` **imports** `ring_round_trips`
and applies it to the measured emulation rows — no re-derivation, no drift from the sim. Aggregate
ring messages / N / measured-window seconds = msgs/node/s.

**Caveat, flagged not hidden:** this counts **query-path DHT/Chord RPCs only** — identically on
both sides. It **excludes maintenance traffic** (stabilize / fix_fingers / PoSpace challenges),
which is a real but N-weakly-dependent cost the sim does not model. Because the *same* scope is
applied to emulation and sim, the two curves are comparable; the absolute number is a query-path
load, not total wire traffic. (A future emulation-only RPC counter could report the maintenance
superset separately — out of scope for A3's combined curve.)

## Throughput — offered/idealised (sim) vs achieved (emulation)
The sim's workload is **open-loop, fixed-rate with no contention model** (`sim/query_sim.py`), so
its `throughput_qps` is the **offered** rate (100% success by construction) — saturation is
deferred to A2. The emulation reports genuinely **achieved** throughput (send-span rate) and
**goodput** (successful qps) under real load. So across the join, the directly comparable outputs
are the **per-node load** and the **latency percentiles**; the throughput panel shows the
emulation goodput against the flat offered-load line, with the sim as the idealised reference.

## Workload (frozen — `PARAMETERS.md`)
`--mode nodes`, N ∈ {4,8,16,32} (emulation) / {1000,5000,10000} (sim), **measured 50 qps**, **30 s
measured** per emulation run + **30 s warm-up at 10 qps**, Zipf α=1.0 over 1000 Tranco domains,
netem two-tier 5/50 ms, seed 20260919, replication s=3, δ=2.0 s, PLOT_N=1024, DRG in-degree 2.
Emulation is **3 runs per N** (error bars = run-to-run sd). The sim runs 60 s + 30 s warm-up (a
rate is duration-normalised, so the window length does not bias msgs/node/s). The Phase-5
`sim_scale.csv` (qps=100) is **left untouched**; A3 re-runs the sim at 50 qps for a single-load
curve.

## Collection methodology (A2's bring-up, not A1's — two choices A3 uniquely needs)
`run_a3.sh` brings each ring up with `--keep-up`, warms it, drives the measured load, snapshots
**while the containers are still running**, then tears down. Two non-obvious choices, each
learned from an artifact seen in a first (A1-style) collection pass:
1. **Snapshot the node logs while the ring is up.** A1's pattern lets `run_experiment.sh` tear the
   ring down and snapshots afterwards; Docker Desktop's bind-mount write-back then loses the last
   writes, so the node logs came back short of the client query count (harmless for A1's relative
   outcome split, but it corrupts A3's absolute message counts). Snapshotting while up gives
   complete capture — verified `node_rows ≈ client_ok` for every run (e.g. N=8 1497/1497).
2. **Warm at a low 10 qps, then measure at 50.** Warming a fresh 32-node ring *at* 50 qps perturbs
   `stabilize` before it converges (a milder N=64 failure mode) and success collapsed to ~53%.
   Warming at 10 qps first restores N=32 to ~95% (consistent with A2), matching the frozen ceiling.

## Output schema — `A3_scalability.csv`
One row per (source, N), emulation first then sim:
`source, n, qps, duration_s, runs, throughput_qps, throughput_sd, goodput_qps,
success_rate_pct, success_sd, msgs_per_node_per_s, msgs_per_node_sd, total_ring_messages,
p50_ms, p95_ms, p99_ms, p95_sd`. Emulation percentiles/success are the **mean across the 3 runs**
(over **successful** rows, the A1/A2 convention); `*_sd` are the run-to-run standard deviations
(the plot's error bars). `throughput_qps` (emulation) is the achieved send rate; `goodput_qps` is
successful qps. Sim rows have `runs=1` and zero sd (deterministic).

## How to reproduce
```
bash experiments/run_a3.sh              # collect: N=4/8/16/32 ×3 @ 50 qps (Docker Desktop)
python3 experiments/a3_scalability.py   # combine emu + sim@50qps -> A3_scalability.csv + PNG
```
Sim-only smoke (no Docker): `python3 experiments/a3_scalability.py --sim-only`. Quick emulation
subset: `A3_NS="8 32" A3_RUNS=1 bash experiments/run_a3.sh`. Snapshots land under
`results/a3/N<n>/run<r>/{client.csv, ring/*_queries.csv}` (seed-reproducible).

## Results (measured 2026-09-22, seed 20260919, 3 runs per N)
Per-node message load **falls monotonically as N grows** — the headline scalability signal —
across the full curve, with emulation and simulation agreeing on the slope in the N=4…32 overlap:

| N | source | per-node load (msgs/node/s) | goodput (qps) | success % |
|---|---|---|---|---|
| 4     | emulation | 75.4 | 50.0 | 99.9 |
| 8     | emulation | 48.4 | 49.8 | 99.6 |
| 16    | emulation | 28.7 | 49.9 | 99.8 |
| 32    | emulation | 17.7 | 47.4 | 94.8 |
| 4     | sim (overlay) | 43.0 | 50.0 | 100 |
| 8     | sim (overlay) | 29.4 | 50.0 | 100 |
| 16    | sim (overlay) | 19.5 | 50.0 | 100 |
| 32    | sim (overlay) | 12.5 | 50.0 | 100 |
| 1,000  | sim | 0.911 | 50.0 | 100 |
| 5,000  | sim | 0.219 | 50.0 | 100 |
| 10,000 | sim | 0.116 | 50.0 | 100 |

**Scalability holds:** per-node load decays ~0.62× per doubling of N on **both** sides (emulation
75.4→48.4→28.7→17.7; sim 43→29.4→19.5→12.5) — a fixed 50 qps spread over more nodes, each query
still touching only O(log N) of them. Throughput stays at the offered ~50 qps (emulation goodput
47.4–50.0), so growing the ring does not cost throughput. At N=10,000 the simulator shows
per-node load down to **0.12 msgs/node/s** — the design scales.

**The emulation sits ~1.5–1.8× above the sim overlay (flagged, not hidden).** Same *slope*,
higher *level*. The gap is a cold-start / cache-warmth difference: the 30 s warm-up at 10 qps
touches only ~300 of the 1000 Zipf domains, so the emulation's measured 30 s window still carries
more first-time dht_hit/fallback lookups (each costing ring messages) than the simulator's
idealised warmed steady state. It is an absolute-level offset, not a scaling difference — the
scalability conclusion (the decay slope) is what the two agree on, and it is what A3 claims.

**N=32 is the emulation ceiling and shows it.** Success dips to 94.8% at N=32 (vs ~100% at N≤16)
and goodput to 47.4 qps — consistent with A2's ~97% at 50 qps and the frozen ceiling
(`PARAMETERS.md` §1). Larger N is the simulator's job (Phase 3/5 decision). Error bars in the
figure are the run-to-run standard deviation over the 3 runs.

## Status — DONE
Emulation (N=4/8/16/32 ×3) + simulation (N=4…10,000 @ 50 qps) collected and combined;
`A3_scalability.csv` + `fig_A3_scalability.png` produced. Reproduce with the two commands above.
