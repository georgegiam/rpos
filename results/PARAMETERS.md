# Frozen experimental parameters — Phase 4

These are the default parameters for **all** Phase 5–8 experiments unless an experiment
explicitly sweeps one of them (e.g. A4 sweeps `s`, A7 sweeps plot size). They were exercised
and validated during Phase 4 (sanity checks + baseline) on 2026-09-21 and are frozen here so
every later run — and any examiner re-run — starts from the same, written-down configuration.

Machine: Apple M4, 10 cores, 16 GiB RAM (CLAUDE.md §5). All runs use Docker Desktop 29.8.0.

---

## 1. Frozen defaults

| Parameter | Value | Where set |
|---|---|---|
| Replication factor `s` | **3** | `node/storage.py` (`S = 3`) |
| PoSpace challenge timeout δ | **2.0 s** (test scale) | `gen_nodes_compose.py --challenge-timeout`; `CHALLENGE_TIMEOUT` |
| PoSpace eviction | after **3 consecutive** failed challenges | `node/pospace_admission.py` |
| Network delay — intra-region | **5 ms** one-way (≈10 ms RTT) | `netem.sh` `SAME_MS`; `run_experiment.sh --same-ms` |
| Network delay — inter-region | **50 ms** one-way (≈100 ms RTT) | `netem.sh` `CROSS_MS`; `run_experiment.sh --cross-ms` |
| Regions | **2** (assigned by index, deterministic) | `netem.sh`; `run_experiment.sh --regions` |
| Per-query timeout | **5.0 s** | `query_gen.py --timeout` |
| Maintenance interval | **1.0 s** | `MAINT_INTERVAL` (`run_ring_node.py`) |
| — stabilize + check_predecessor | every round (**1.0 s**) | `run_ring_node.py` maintenance loop |
| — top-finger refresh | ~every **4.0 s** | `run_ring_node.py` (`fingers_every`) |
| — full `fix_fingers` | ~every **4.0 s** (spaced from challenge) | `run_ring_node.py` |
| — periodic PoSpace challenge | ~every **5.0 s** | `run_ring_node.py` (`challenge_every`) |
| Plot size `PLOT_N` (test scale) | **1024** leaves | `gen_nodes_compose.py --plot-n` |
| DRG in-degree δ (v3 scheme) | **2** | `gen_nodes_compose.py --drg-indegree` |
| Workload | **Zipf α = 1.0** over **1000 Tranco** domains | `query_gen.py`; `dns/generate_zones.py --count 1000` |
| Zone TTLs | 300–3600 s | `dns/generate_zones.py` |
| Warm-up | **30 s** of ring load (CSV discarded) | `run_experiment.sh --warmup` |
| RNG seed | **20260919** | `run_experiment.sh --seed` |
| Emulation scale ceiling | **N = 32** (N=64 → Phase 5 simulator) | Phase 3 decision |

Notes:
- δ = 2.0 s is the **test-scale** admission timeout for the small (`PLOT_N=1024`) plots used in
  emulation, not the thesis-scale δ discussed in Phase 1 (which depends on final DRG in-degree
  sign-off). The two are distinct; do not conflate them.
- Warm-up of 30 s is what made N=32 converge and populate the DHT before the measured window
  (Phase 3). It is used for the nodes-mode runs; the Unbound baseline uses 15 s (a warm cache
  needs less).

---

## 2. Sanity check — measured hops vs Chord theory

Chord expected lookup length ≈ ½·log₂N. Measured = median hop count aggregated across every
node's `results/ring/<j>/queries.csv` for the **measured** window only (warm-up discarded),
netem on, 10 qps, 30 s.

| N | expected ≈½·log₂N | measured (median) | difference |
|---|---|---|---|
| 8  | 1.5 | 2 | +0.5 |
| 32 | 2.5 | 3 | +0.5 |

Both within +0.5 hop of theory (well under the 1.5-hop "that's a bug" threshold) → routing is
behaving as Chord predicts; no bug. The small positive offset is expected: the median is an
integer over a right-skewed distribution, and a fraction of lookups traverse replicas /
fallback. (N=8 mean 2.33, N=32 mean ≈2.89.)

---

## 3. Unbound baseline (mode=host)

Same DNS hierarchy and netem two-tier delays as the resolver ring. Offered-load ramp, 30 s
each, 15 s warm-up, seed 20260919. Raw data: [`baseline_unbound.csv`](baseline_unbound.csv).

| offered qps | success | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|
| 10  | 100.0% | 3.47 | 132.87 | 214.94 |
| 50  | 100.0% | 2.01 | 118.00 | 207.95 |
| 100 | 100.0% | 1.35 | 113.93 | 203.14 |
| 200 | 100.0% | 1.09 | 5.06   | 201.87 |
| 400 | **96.7%** | 1.03 | 1.70 | 111.85 |

- **Reference latency (unsaturated, 10 qps):** p50 **3.5 ms**, p95 **132.9 ms**, p99 **214.9 ms**.
  The tail reflects cold-cache misses recursing through the emulated hierarchy over netem
  (cross-region ≈100 ms RTT); p50 is a warm-cache hit.
- **Maximum sustained QPS at ≥99% success: 200 qps** (100.0%). At **400 qps** success falls to
  **96.7%**, so saturation lies **between 200 and 400 qps** in this testbed.
- We did **not** push past 400 qps: at ≥800 qps the closed-loop query generator (64 worker
  threads) becomes the bottleneck — saturated queries hit the 5 s timeout and back up behind
  the worker pool during drain — so higher points would measure the generator, not Unbound.
  The ≥99% ceiling (200 qps) and the crossing point (200–400 qps) are already established.

---

## 4. Stability — N=32 repeated 3× (nodes mode)

qps 10, duration 30 s, warmup 30 s, netem on. Seeds identical across runs (reproducibility);
run-to-run variation reflects container scheduling / stabilize timing, not workload.

| run | success | p50 (ms) |
|---|---|---|
| 1 | 99.3% (298/300) | 524.5 |
| 2 | 100.0% (300/300) | 491.9 |
| 3 | 100.0% (300/300) | 511.7 |

Success spread **99.3–100.0%** (< 10% window) and p50 spread **491.9–524.5 ms** (< 2×) →
**stable**. Hop median = 3 in every run.
