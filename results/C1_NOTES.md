# C1 — final partial-storage attack on v3 DRG: methodology notes (issue #50, Phase 8, examiner point (i))

Reproducible trail for the C1 retention experiment. Numbers live in
[`C1_retention_attack.csv`](C1_retention_attack.csv) and
[`fig_C1_retention.png`](fig_C1_retention.png); this file records *how* they are produced and the
honest caveats (CLAUDE.md §2 "measure, don't assert" / "flag, don't hide").

## What C1 measures

The **definitive time–space trade-off of the proposed scheme**: *how much storage can a cheater
discard and still answer a PoSpace challenge within the response timeout δ?* This is examiner point
**(i)** ("what is lost by gaining efficiency") for the *proposed* side; the Chia comparison rows
(C2–C5) build on it.

A cheater plots the real v3 DRG tree once (it must publish the real Merkle root), then keeps only a
fraction of the labels and discards the rest. A v3 challenge opens node *i* **and all its DRG
parents**; to answer, each discarded label must be re-materialised by recomputing its whole
**back-cone** — follow the DRSample parents back until every dependency bottoms out at a retained
label ([`phase1/attack_v3_retain.py::backcone_mask`](../phase1/attack_v3_retain.py)). Because the
graph is depth-robust, that back-cone is a large fraction of *N* at any small storage, so the
recompute is slow. C1 quantifies exactly that and extrapolates it to the thesis plot.

### Headline finding — a real space lower bound; a usable δ exists

Extrapolated to the thesis plot **N = 3,355,443,200** at the measured native rate **20.36 MH/s**
(single-core SHA-256, CLAUDE.md §5), against the loosest thesis response timeout **δ = 5 s**:

| DRG in-degree δ | cheater may discard at most | i.e. must keep | recompute if it keeps less | verdict |
|---|---|---|---|---|
| **δ = 2** (node default) | **~50% of the plot** | ≥ 50% labels (≈ 75% tree) | keep 25% → **13.0 s** ≫ 5 s | separates |
| **δ = 4** | **~25%** | ≥ 75% labels (≈ 87.5% tree) | keep 50% → **16.8 s** | separates (strong) |
| **δ = 8** | **~0%** | ~100% labels | keep 75% → **6.8 s** | separates (near-full) |

An honest node answers the same challenge in ~tens of ms (it reads the stored labels; A7). So a
response timeout **δ ≤ 2 s cleanly separates honest from cheater**; the unlimited-core parallel
floor ≈ **5.15 s** (below) makes δ = 5 s marginal, so prefer δ ≤ 2 s. This reproduces Phase 1
`FIX_A.md` (back-cone ≈ 0.45–0.5·N → ~75 s at 5% storage) with the repo-standard seed — a sanity
gate that the imported physics is intact.

**Contrast (what Fix A bought).** The broken v2 chain is a *path graph*: a cheater beats every
feasible δ storing parts-per-million (the ~1.5/k checkpoint attack, `FINDINGS.md`). v3's
depth-robust graph turns the same storage saving into an Ω(N) recompute — the trade-off collapses.

## Metric

- **back-cone hashes** — SHA-256 evaluations the cheater must perform to answer one challenge =
  size of the DRG back-cone of the opened nodes (node *i* + its parents) over the retained-label
  set. Exact, structural (graph traversal, no hashing). Median & p99 over the sampled challenges.
- **recompute time** `= back-cone hashes / 20.36 MH/s` — the modeled single-core native wall-clock.
  Anchored by a real timed reconstruction (`source=wallclock_anchor`, see caveats).
- **success vs δ** — `1` iff recompute time ≤ δ (the cheater answers in time), for δ ∈ {1, 2, 5} s.
  A per-config threshold indicator (the back-cone size has low variance at fixed config), not a
  sampled rate.
- **depth** — back-cone critical-path length = sequential work even with unlimited cores → the
  parallel-attacker floor.
- **φ (back-cone fraction)** `= back-cone hashes / N` — shown ~flat across the measured N, which is
  what licenses the thesis-scale extrapolation `recompute = φ·N / rate`.
- **pass_rate** — real `verify_v3` acceptance of the reconstructed proof (`source=validated`); 1.0
  by construction, confirmed by actually running the attack.

## Results (seed 20260919, native rate 20.36 MH/s; measured N ∈ {2^18, 2^20, 2^22})

**Measured back-cone fraction φ (δ=2), ~flat in N → clean extrapolation:**

| storage kept (labels) | φ @ 2^18 | φ @ 2^20 | φ @ 2^22 | → thesis recompute |
|---|---|---|---|---|
| 1% | 0.488 | 0.499 | 0.494 | **81.5 s** |
| 5% | 0.503 | 0.473 | 0.488 | 80.4 s |
| 10% | 0.344 | 0.374 | 0.369 | 60.8 s |
| 25% | 0.070 | 0.082 | 0.079 | 13.0 s |
| 50% | ~0 | ~0 | ~0 | ~0 s (cheater passes) |

(φ is the per-N value in the CSV; the extrapolated row uses the **median over N**. The saturated
plateau ≈ 0.49 carries ±~0.05 sampling noise — reported, not smoothed.)

**Real-reconstruction validation (`source=validated`):** every anchor at a power-of-two stride
(keep 1/2, 1/4, 1/8, 1/16) really plots, discards, reconstructs from the retained set and checks
`verify_v3` → **pass_rate = 1.0** (the attack genuinely works, it is not just a count). At the
smallest storage the real round-trip is *skipped* when a challenge's back-cone exceeds the
200 k-label reconstruction cap (shown as an empty `pass_rate`); the structural back-cone count is
still exact there. **Wall-clock anchor (`source=wallclock_anchor`):** a real Python recompute runs
at ~0.9 MH/s (pure interpreter overhead, ~22× the native floor) and matches the modeled native time
(e.g. 101 619 labels in 108 ms Python → modeled 4.99 ms native); the thesis timing uses the native
20.36 MH/s floor per repo convention.

## The new driver (no frozen edit — CLAUDE.md §2)

New code in new files only — [`experiments/c1_retention.py`](../experiments/c1_retention.py) +
[`experiments/run_c1.sh`](../experiments/run_c1.sh). It **imports, never copies**, the frozen
retention physics: `backcone_mask` / `backcone_depth` / `parent_table` / `validate_config` from
[`phase1/attack_v3_retain.py`](../phase1/attack_v3_retain.py); `plot_v3` / `commit_v3` / `verify_v3`
/ `_label` from [`phase1/pospace_drg.py`](../phase1/pospace_drg.py); `parents` from
[`phase1/drg.py`](../phase1/drg.py); and the thesis plot size `REAL_PLOT_N` from
[`node/pospace_admission.py`](../node/pospace_admission.py). The thesis-scale model mirrors
[`phase1/delta_separation_drg.py`](../phase1/delta_separation_drg.py) (φ·N / rate).

Byte-identical (imports/reads only): `rpos/rpos.py`, **all of `phase1/*`**, **all of `node/*`**.

## Workload (frozen — PARAMETERS.md / CLAUDE.md §5)

Native rate 20.36 MH/s (`phase1/results/chainrate.csv`); seed 20260919 (phase1 used seed 1 — the
pk differs, so absolute counts differ slightly, but φ and the separation thresholds are
seed-robust); DRG in-degree δ ∈ {2, 4, 8} (headline 2 = node default `DRG_INDEGREE`); measured
N ∈ {2^18, 2^20, 2^22}; thesis N = 3,355,443,200; response-timeout grid {1, 2, 5} s.

## Honest caveats (flag, don't hide — CLAUDE.md §2)

1. **Storage axis.** The headline is the **label fraction** (fraction of the N plot labels kept).
   The CSV also reports `total_store_frac` (labels + internal Merkle nodes, the FIX_A axis): keep
   50% labels → 0.75 tree, 25% → 0.375, etc. The two must not be conflated.
2. **Back-cone extrapolation.** φ is measured over 2^18–2^22 (~flat) and applied at the thesis N,
   ~800× beyond the measured range. This relies on **DRSample's asymptotic depth-robustness
   guarantee, not a re-proof at thesis N** (FIX_A §5). The plateau φ ≈ 0.49 carries ~±0.05 sampling
   noise at the few-challenge large-N points.
3. **Parallel attacker.** The verdict is the **sequential single-core** model. An unlimited-core
   attacker is bounded below by the back-cone *critical-path depth*, not its size; the theory floor
   ≈ (N/log₂N)/rate ≈ **5.15 s** (`par_floor_s` column) makes the loosest δ = 5 s marginal. Prefer
   δ ≤ 2 s, robust under both models. This is a caveated sensitivity, **not** the verdict basis.
4. **Merkle-rebuild term.** C1's headline back-cone counts the DRG label recomputes (the Fix-A
   cost). The frozen attack additionally folds a lower-Merkle-subtree rebuild; at the small-storage
   regime that governs the verdict it is < 1% of the back-cone, so it changes no threshold.
5. **Awaiting sign-off (CLAUDE.md, Phase 1 "Open").** The DRG in-degree δ, the target
   depth-robustness, and whether a stacked DRG is needed still require **cryptographer / supervisor
   sign-off** before any *final* thesis claim. C1's numbers are provisional on the v3-DRG freeze.

## How to reproduce

```bash
bash experiments/run_c1.sh                      # full sweep -> CSV + PNG + stdout
C1_QUICK=1 bash experiments/run_c1.sh           # drop N=2^22 (fast)
python3 experiments/c1_retention.py --fractions 1,10,50,100 --deltas 2 --no-plot   # smoke
```

Needs `python3` with numpy + matplotlib (the same env as A1–B7); no Docker.

## Output schema (`C1_retention_attack.csv`)

| column | meaning |
|---|---|
| `source` | `measured` (sweep) / `validated` (real verify_v3 at a power-of-two stride) / `wallclock_anchor` (one timed real recompute) / `extrapolated` (thesis N) |
| `N`, `log2N` | plot size (leaves) for this row; `extrapolated` rows use REAL_PLOT_N |
| `delta` | DRG in-degree (2 = node default headline; 4, 8 secondary) |
| `label_frac_pct` | storage kept, as a % of the plot's N labels (the headline axis) |
| `retained_labels` | label count kept = round(label_frac · N) |
| `total_store_frac` | kept storage as a fraction of the full honest Merkle tree (FIX_A axis) |
| `back_cone_hashes_median`, `_p99` | SHA evaluations to answer one challenge (median / p99) |
| `depth_median` | back-cone critical-path depth (−1 when the cone exceeds the depth budget) |
| `saturated` | 1 if a challenge's back-cone exceeded the 300 k depth budget (recompute ≈ full replot) |
| `recompute_time_s_median`, `_p99` | back_cone_hashes / 20.36 MH/s (modeled native wall-clock) |
| `phi` | back_cone_hashes_median / N (per-N for measured; median-over-N for extrapolated) |
| `par_floor_s` | parallel-attacker floor: depth/rate (measured) or (N/log₂N)/rate (extrapolated) |
| `success_1s`, `success_2s`, `success_5s` | 1 iff recompute_time ≤ δ (cheater answers in time) |
| `pass_rate`, `pass_validated` | real verify_v3 acceptance (validated rows); empty if the cone exceeded the reconstruction cap |
| `challenges` | challenges sampled for this config |
| `note` | per-row provenance (φ spread, anchor stride, real-recompute timing) |
