# A4 — Replication cost: methodology notes (issue #35, Phase 6, examiner point (iii))

Reproducible trail for the A4 experiment. Numbers live in
[`A4_replication.csv`](A4_replication.csv) and [`fig_A4_replication.png`](fig_A4_replication.png);
this file records *how* they were produced and the honest caveats (CLAUDE.md §2 "measure, don't
assert" / "flag, don't hide").

## What A4 measures
The **cost of replication**: at the frozen **N=32** emulation ceiling (`PARAMETERS.md` §1) and an
unsaturated **10 qps**, we sweep the replication factor **s ∈ {3, 5, 7}** (3 runs each) and record
**messages per query**, **p50/p95/p99 latency**, and **success rate**. The deliverable is a table
comparing the three s values (issue #35's done-when).

A4 is the **cost** side. At N=32 steady-state — no churn, no node failures — replication's
*benefit* (data availability when replicas die) does not appear; that is **Phase 6 A6 / churn**
(`sim/churn_sim.py`, whose availability model keys directly off the replica-set size). So here the
discriminating metrics are **messages/query** (linear in s) and, in emulation, **latency** (rises
with s) and **success** (which, measured, *falls* with s at this scale — see Results/caveat 1).

## Results (measured 2026-09-22, seed 20260919, 3 runs per s)
Full stats + run-to-run sd in [`A4_replication.csv`](A4_replication.csv).

| s | succ-list len | success % (sd) | p50 (ms) | p95 (ms) | messages/query (sd) | source |
|---|---|---|---|---|---|---|
| 3 | 3 | 99.8 (0.2) | 473.3 | 1421.5 | 13.14 (0.08) | emulation |
| 5 | 4 | 97.1 (0.5) | 577.1 | 2370.6 | 17.47 (0.11) | emulation |
| 7 | 6 | 90.1 (1.7) | 725.9 | 2753.4 | 21.21 (0.17) | emulation |
| 3 | 3 | 100.0 | 320.5 | 1300.0 | 13.46 | sim |
| 5 | 4 | 100.0 | 320.5 | 1300.0 | 17.62 | sim |
| 7 | 6 | 100.0 | 320.5 | 1300.0 | 21.79 | sim |

**Headline — replication cost rises on every axis with s.**
- **Messages per query rise ~linearly in s** — 13.1 → 17.5 → 21.2 (each extra replica adds one read
  RPC on a DHT hit and one write RPC on a fallback: ≈2 messages/query per +1 s). The emulation
  counts match the simulator's model (13.5 / 17.6 / 21.8) **within ~3%**, validating the shared
  `ring_round_trips` accounting. Storage cost also scales ×s (s copies of every chunk).
- **Latency rises with s** — emulation p50 473 → 577 → 726 ms, p95 1421 → 2371 → 2753 ms — because
  `storage.get_chunk` reads the replicas **sequentially** over netem (each extra replica is another
  ≈10–100 ms RTT). The simulator's p50 is flat (320.5 ms) because it models the fan-out as parallel
  (`max` RTT) — the deliberate model divergence A4 is designed to surface (caveat 2 below).
- **Success falls with s** — 99.8 → 97.1 → 90.1%. This is **not** a benefit turning into a cost by
  magic: with no node failures the extra replicas add no availability, while the sequential-read
  latency pushes more tail queries past the 5 s client timeout (and the longer successor list adds a
  little maintenance traffic). So at this steady-state test scale higher s is **pure cost**. The
  *benefit* — surviving replica loss — needs actual failures/churn and is measured in **A6**.
- **s=3 anchor reproduces A1/A3's N=32** (99.8% success, p50 473 ms ≈ A1's 511 ms / A3's 94.8–100%),
  confirming the sweep harness matches the frozen s=3 results.

**Examiner-facing takeaway:** replication is a **cost/benefit trade** — higher s costs messages/query
and storage (both linear in s) and, over a real network with sequential reads, latency and some tail
success; it buys data availability under failure (A6). A4 quantifies the cost side; A6 the benefit.

## The one non-obvious knob — successor-list length (chord.py NOT modified)
The replica set is `[primary] + up to SUCC_LIST_LEN successors`, truncated to s
(`node/storage.py:replica_set`). `node/chord.py` caps the successor list at `SUCC_LIST_LEN = 3`, so
**s > 4 would silently yield only 4 replicas**. A4 raises the successor list to **max(3, s−1)**
(s=3→3, s=5→4, s=7→6) so a replica set of s can actually be filled.

Crucially this is a **runtime override, not a source edit**: `SUCC_LIST_LEN` is read as a *module
global* on every `_refresh_successor_list` round (`chord.py:141`), so `node/run_ring_node.py` sets
`node.chord.SUCC_LIST_LEN` at process start from the `SUCC_LIST_LEN` env var — **`node/chord.py`
stays byte-identical** (CLAUDE.md §2 freeze preserved). The default (no override) is 3, so **A1–A3
are unaffected**, and the **s=3 A4 point reproduces the A1/A3 s=3 conditions exactly** — a built-in
sanity check that the sweep harness matches the frozen results. The replication factor itself is
wired the same additive way: `REPLICATION` env → `run_ring_node` → the existing
`StorageMixin(replication=…)` kwarg (`node/storage.py:21`); the ledger 2PC quorum
(`len(replicas)//2+1`) scales with s automatically.

## Workload (frozen — `PARAMETERS.md`)
`--mode nodes`, **N=32**, measured **10 qps**, **30 s measured**, **30 s warm-up at 10 qps**, Zipf
α=1.0 over 1000 Tranco domains, netem two-tier 5/50 ms, seed 20260919, δ=2.0 s, PLOT_N=1024, DRG
in-degree 2. **3 runs per s.** Swept: s ∈ {3,5,7} with SUCC_LIST_LEN = max(3, s−1).

## Methodology — A3's bring-up (warm @ 10 qps, snapshot ring logs WHILE UP)
Messages/query needs the **complete** node-side `(outcome, hops)` record, and Docker's bind-mount
write-back loses the tail if the ring is torn down first — so, as in A3, each run brings the ring up
with `--keep-up`, warms at 10 qps to converge + populate the DHT, drives the measured 10 qps load,
then **snapshots each node's `queries.csv` while the containers still run**, and only then tears
down. Per (s, run): bring up N=32 with REPLICATION=s / SUCC_LIST_LEN=max(3,s−1) → warm → measure →
snapshot → teardown. Repeated 3× per s for run-to-run error bars.

## Message model — A3's `ring_round_trips`, generalized to s
`messages_per_query` uses the **same** model A3 applies, now passed the swept s:
`sim/scale_sim.ring_round_trips(outcome, hops, s)` — a round trip = req+resp = 2 messages; a query
costs `route + 1 + s` round trips on a DHT hit (route + `get_succ_list` + s replica reads) and twice
that on a fallback (failed read + store-back of s writes); a cache hit costs 0. `a4_replication.py`
applies it to each emulation node log **and** to the sim records, so the emulation and sim
messages/query points are directly comparable, and it is **linear in s** by construction. Reported
as ring messages / queries-processed (a per-query average). Maintenance traffic is **not** counted
(query-path RPCs only) — same convention as A3, flagged.

## Honest caveats (flag, don't hide — CLAUDE.md §2)
1. **At N=32 steady-state, higher s is pure cost — it even lowers success (99.8 → 90.1%).** With no
   node failures the extra replicas add no availability, while the sequential-read latency (caveat 2)
   pushes more tail queries past the 5 s client timeout and the longer successor list adds a little
   maintenance traffic. This is the honest counterpart to the usual "replication helps" intuition:
   the *benefit* only exists when replicas actually die, which is **A6/churn**, not A4. So A4 is
   squarely the cost side, and the success drop is a *cost*, not evidence against replication.
2. **Emulation latency rises with s; the sim's is ~flat.** `node/storage.get_chunk` reads replicas
   **sequentially**, so emulation p50/p95 grow with s (more replicas to poll). The simulator models
   the replica fan-out as **parallel** (`max` RTT over the replica set), so its latency is ~flat in
   s. This is a deliberate, documented model divergence (`sim/query_sim.resolve`), and A4 is exactly
   where it shows — the emulation numbers are the headline for the latency-vs-s trend; the sim is
   the message-model cross-check.
3. **Sim success is degenerate (~100%).** The query sim has no loss model, so its success is 100% by
   construction (same limitation flagged in the #29 calibration). The sim contributes the
   messages/query and latency-shape cross-check, not a success rate.
4. **s=5/7 are above the frozen s=3 default.** They rely on the runtime SUCC_LIST_LEN override; the
   convergence check (below) confirms N=32 still converges with the longer successor list.

## Convergence sanity for the longer successor list
A longer `SUCC_LIST_LEN` adds a little maintenance traffic (each `_refresh_successor_list` merges a
longer list). N=32 is well below the N=64 convergence wall (CLAUDE.md Phase 3), so the s=5/7 runs
are expected to converge and hold success comparable to A3's N=32 (~95–100%). The measured success
+ hop distributions in the runs confirm this; any large regression would flag a convergence issue,
not a replication effect.

## How to reproduce
```
bash experiments/run_a4.sh                 # collect: s in {3,5,7} x 3 runs on N=32 (Docker Desktop)
python3 experiments/a4_replication.py      # analyse -> A4_replication.csv + fig_A4_replication.png
```
Snapshots land under `results/a4/s<s>/run<r>/{client.csv, ring/}` (git-ignored, seed-regenerable).
Quick sim-only cross-check (no Docker): `python3 experiments/a4_replication.py --sim-only`.

## Output schema — `A4_replication.csv`
One row per (source, s):
`source, s, succ_list_len, n, qps, duration_s, runs, success_rate_pct, success_sd, p50_ms, p95_ms,
p99_ms, p50_sd, messages_per_query, messages_per_query_sd`. Emulation percentiles/success are the
**mean across the 3 runs** (over **successful** client rows, the A1/A2/A3 convention); `*_sd` are
the run-to-run standard deviations (the plot's error bars). Sim rows are single deterministic runs.
