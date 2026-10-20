# C3 — detection probability vs challenges per round: methodology notes (issue #52, Phase 8, examiner point (i))

Reproducible trail for the "how many challenges catch a cheater?" experiment. Numbers live in
[`C3_detection.csv`](C3_detection.csv) and [`fig_C3_detection.png`](fig_C3_detection.png); this file
records *how* they are produced and the honest caveats (CLAUDE.md §2 "measure, don't assert" /
"flag, don't hide"). Driver: [`experiments/c3_detection.py`](../experiments/c3_detection.py)
(+ [`run_c3.sh`](../experiments/run_c3.sh)). Depends on the same frozen DRG physics as C1 (#50) and
the node's eviction policy.

## What C3 measures

C1 (#50) gave the storage→recompute-time trade-off and C2 (#51) the false-accept/false-reject rates
vs δ — both **per-challenge** statements. The node, however, challenges peers **periodically**
(~every 5 s) and evicts after **MAX_FAILS = 3 consecutive** failed challenges
(`node/pospace_admission.py`). C3 closes the loop and answers the operational question literally:

> **"How many periodic challenges does it take to catch a cheater with high probability?"**

For a cheater keeping label-fraction ρ it derives the per-challenge failure probability `p_fail(ρ)`
two ways and reports the gap, then propagates each to a detection and an eviction curve.

### Headline finding

**Detection is recompute-time bound, not coverage-bound — and below the storage threshold a single
challenge catches the cheater.** At the node default δ_g=2, δ=2 s:

| keep ρ (labels) | p_fail (time-gated) | p_cov (coverage, analytical) | P_detect(1) | P_detect(5) | E[evict] (run of 3) |
|---|---|---|---|---|---|
| 50 % | ≈ 0.00 | 0.875 | 0.00 | 0.00 | ∞ (never) |
| 33 % | ≈ 0.00 | 0.964 | 0.00 | 0.00 | ∞ (never) |
| 30 % | ≈ 0.17 | 0.973 | 0.17 | 0.62 | ~228 ch ≈ 1142 s |
| 25 % | ≈ 0.74 | 0.984 | 0.74 | 0.999 | ~5.6 ch ≈ 28 s |
| 20 % | ≈ 0.89 | 0.992 | 0.89 | 1.00 | ~3.8 ch ≈ 19 s |
| 10 % | ≈ 0.97 | 0.999 | 0.97 | 1.00 | ~3.2 ch ≈ 16 s |

*(Values from the committed pooled-over-N rows; see `C3_detection.csv` `source=empirical_pooled` /
`analytic`. The knee sits at ρ≈25 % for δ_g=2 and is the only regime where the number of challenges
`c` matters: ρ≤20 % is caught by the **first** challenge, ρ≥33 % escapes the timeout entirely.)*

Three readings of the table:

- **Below the threshold (ρ≤20 %), one challenge is enough.** `p_fail≈1`, so the cheater is detected on
  the first challenge and **evicted within MAX_FAILS=3 rounds ≈ 15 s**. Periodic challenging does not
  need many rounds; the storage lower bound bites immediately.
- **At the knee (ρ=25 %), a handful of challenges reaches near-certainty.** `p_fail≈0.74` → one
  challenge catches it 74 % of the time, but **5 challenges give 99.9 %** detection. Because eviction
  needs *consecutive* fails, a lucky pass resets the streak, so **expected time-to-eviction ≈ 5.6
  challenges ≈ 28 s** — still fast, but the gap between "detected" and "evicted" is real and reported.
- **Above the threshold (ρ≥33 %), timing cannot catch the cheater** — but that cheater stored ≥ ~50 %
  of labels (≈ 75 % of the tree), i.e. it paid almost the honest cost and saved almost nothing. This
  is the C1 result restated: the only storage-saving adversary is one the challenge *does* catch.

**The analytical-vs-empirical gap (the issue's explicit ask).** The coverage model
`p_cov = 1 − ρ^(1+avg_indeg)` — "any challenge that opens a discarded label is a catch" — is a **strict
upper bound** on `p_fail` (because {recompute > δ} ⊂ {opened a hole}). The gap is the cheater's
**cheap holes**: discarded labels whose DRG back-cone recomputes *within* δ. It is **maximal at
ρ=50 %** — coverage predicts 87.5 % per-challenge detection, but every opened hole there recomputes in
sub-millisecond time (back-cone ≈ 0, C1), so a timeout catches **0 %**. The two converge toward ρ=10 %
(both ≈ 1). The takeaway for the thesis: *the naive PoRep "coverage" intuition dramatically
over-states detection for a depth-robust graph with a timeout; the real detector is recompute time.*

## Why a microbenchmark, not the Docker testbed

Like A7/B2/B5/C1/C2, C3 needs no Docker. `p_fail` is a property of the frozen DRG **plot graph** — the
distribution of per-challenge back-cone sizes under a retained-label mask — traversed in-process with
the frozen `backcone_mask`. The detection/eviction curves are **exact probability** from the node's
own policy constants (`MAX_FAILS`, challenge period). A containerised ring would only exercise the
**test-scale** admission path (`PLOT_N=1024`, test δ=2 s), whose timing says nothing about the
**thesis-scale** `p_fail` this experiment is about (PARAMETERS.md, response-timeout caveat). The
thesis-scale back-cone is the committed C1 extrapolation, reused here per challenge.

## Metric

Per (DRG in-degree δ_g, cheater storage ρ, measured N), over many random challenges:

- **per-challenge back-cone fraction** `φ_i = back_cone(i, ρ) / N_measured` — the fraction of the plot
  the cheater must recompute to answer challenge `i` (open leaf `i` + its DRG parents, follow parents
  back until they bottom out at a retained label; the frozen `backcone_mask`). C1's quantity, but C3
  keeps the **whole distribution**, not just the median.
- **time-gated per-challenge failure** `p_fail = P(φ_i · N_thesis / CHAIN_RATE > δ) = P(φ_i > φ*)`,
  `φ* = δ·CHAIN_RATE/N_thesis ≈ 0.012137` at δ=2 s. 95 % CI half-width `1.96·√(p(1−p)/M)` in
  `p_fail_ci`. Columns `phi_median`, `phi_p99`, `phi_star`, `p_fail`, `p_fail_ci`.
- **coverage reference** `p_cov = 1 − ρ^(1 + avg_indegree(δ_g))` (column `p_cov`); `avg_indegree(2)=2.0`
  so the δ_g=2 exponent is exactly 3.
- **detection** `P_detect(c) = 1 − (1 − p_fail)^c`, `c ∈ {1,5,10,20,50}` (columns `p_detect_*`).
- **eviction** `P_evict(c)` = run of MAX_FAILS consecutive fails within `c`, an exact absorbing Markov
  chain on the fail streak {0,1,2,evicted} (a pass resets to 0, a fail extends — the node's
  `fail_counts` logic). Columns `p_evict_*`.
- **expected challenges** first fail `E[T1]=1/p`; first run of r=MAX_FAILS `E[Tr]=(1−p^r)/((1−p)p^r)`;
  wall-clock = `E · 5 s`. Columns `e_challenges_first_fail`, `e_challenges_evict`,
  `e_wall_first_fail_s`, `e_wall_evict_s`.

Probabilities are exact/closed-form (byte-reproducible); the self-test cross-checks the Markov eviction
against both the scalar run-recurrence `N(c)=N(c−1)−(1−p)p³N(c−4)` and a seeded Monte-Carlo (agreement
< 0.02), and confirms `p_fail→0` at ρ=50 %, `→1` at ρ=10 %.

## The detection / eviction model (frozen policy — `node/pospace_admission.py`)

- one challenge = one random leaf `i` (`self._rng.randrange(1, n)`); its proof opens `i` + DRG parents;
  `verify_v3` returns one boolean → one Bernoulli(`p_fail`) trial (challenges are i.i.d., fresh `i`).
- `fail_counts[peer]` resets to 0 on a pass, +1 on a fail; `>= MAX_FAILS (=3)` → `_evict`. Hence the
  eviction model is **consecutive** fails (run-of-3), not cumulative.
- challenge period ≈ **5.0 s** (`run_ring_node.py` `challenge_every`), used for wall-clock.
- response timeout δ = **2.0 s** (headline); the DRG in-degree δ_g (also written `delta` in the frozen
  code) is a **distinct** parameter — C3 keeps the two apart.

## The new driver — no frozen artifact touched

- New: `experiments/c3_detection.py`, `experiments/run_c3.sh`, this file.
- Imported, never copied (CLAUDE.md §2): `phase1/attack_v3_retain.py` (`parent_table`,
  `backcone_mask`), `phase1/drg.py` (`parents`), `phase1/delta_separation_drg.py` (`avg_indegree`),
  the shared chain-rate loader over `phase1/results/chainrate.csv`.
- Read only: `node/pospace_admission.py` (`REAL_PLOT_N`, `MAX_FAILS`). `rpos/rpos.py`, all of
  `phase1/*` and `node/*` stay byte-identical.

## Honest caveats (flag, don't hide — CLAUDE.md §2)

1. **Inherited C1 extrapolation.** `p_fail` gates the per-challenge back-cone fraction φ against the
   **thesis-scale** threshold φ*=δ·rate/N. φ is measured at 2^18–2^22 and applied to N_thesis ~800×
   beyond that range (DRSample's asymptotic depth-robustness, not a re-proof). C3 adds no new
   extrapolation beyond C1's; it reports `p_fail` **per measured N as a band** (the `source=empirical`
   rows; the figure shades it) precisely because the knee at ρ≈25 % is a finite-size / percolation
   regime where the per-N spread is widest. Across 2^18–2^22 that spread is small (≤ ~0.03).
2. **Parallel attacker.** φ* uses the **sequential** native SHA-256 rate (20.36 MH/s, CLAUDE.md §5).
   An unlimited-core attacker is bounded below by the back-cone critical-path depth (floor ≈ 5.15 s,
   C1/C2); at the headline δ=2 s that floor is above δ so it does not loosen the verdict, but it would
   matter for δ ≥ 5 s — carried as a flagged sensitivity, not the verdict basis.
3. **Detection ≠ eviction.** `P_detect` (≥1 fail, the issue's formula) is **optimistic** vs the node's
   actual **consecutive**-fail policy: a cheater with `p_fail < 1` can pass by luck and reset the
   streak, so time-to-eviction exceeds time-to-first-detection (e.g. ρ=25 %: detected in ~1.4
   challenges but evicted in ~6). Both are reported; the eviction columns are the operational truth.
4. **DRG in-degree δ_g awaits sign-off.** C3 reports {2, 4, 8}; raising δ_g moves the knee to higher ρ
   (δ_g=4 catches even a 50 %-keeper), i.e. a more aggressive detector at the cost of larger proofs
   (C1/A7). Choice of δ_g / target depth-robustness remain open for the cryptographer/supervisor
   (CLAUDE.md, Phase 1 "Open"). Headline is the node default δ_g = 2.
5. **Lower-Merkle rebuild term omitted** (as in C1): the back-cone count excludes the < 1 % lower-tree
   rebuild; at ρ where `p_fail` is intermediate the back-cone dominates, so it does not move the knee.

## How to reproduce

```bash
bash experiments/run_c3.sh                 # self-test, then CSV + figure
# or directly:
python3 experiments/c3_detection.py --self-test
python3 experiments/c3_detection.py                 # full sweep (~tens of minutes at δ_g∈{2,4,8})
python3 experiments/c3_detection.py --quick --indegrees 2   # fast: drop N=2^22, headline in-degree
```

Deterministic (fixed seed 20260919) → re-runs are byte-identical.

## Output schema (`C3_detection.csv`)

| column | meaning |
|---|---|
| `source` | `empirical` (per measured N, band member), `empirical_pooled` (pooled over N, headline), or `analytic` (coverage reference) |
| `drg_indegree` | DRG in-degree δ_g ∈ {2,4,8} |
| `storage_frac_pct` | cheater: % of plot **labels** kept |
| `N_measured` | measured plot size (0 for pooled/analytic rows) |
| `challenges` | number of sampled challenges behind this row (0 for analytic) |
| `phi_median`, `phi_p99` | per-challenge back-cone fraction φ_i percentiles (blank for analytic) |
| `phi_star` | threshold φ*=δ·rate/N_thesis above which recompute > δ |
| `resp_delta_s` | response timeout δ (s) |
| `p_fail` | per-challenge failure prob (time-gated for empirical rows; = `p_cov` for analytic) |
| `p_fail_ci` | 95 % CI half-width on `p_fail` (empirical only) |
| `p_cov` | coverage upper bound 1 − ρ^(1+avg_indeg) |
| `p_detect_{1,5,10,20,50}` | P(≥1 fail in c challenges) |
| `p_evict_{1,5,10,20,50}` | P(run of MAX_FAILS consecutive fails in c challenges) |
| `e_challenges_first_fail`, `e_challenges_evict` | expected challenges to first fail / first eviction |
| `e_wall_first_fail_s`, `e_wall_evict_s` | the same × ~5 s challenge period |
| `challenge_period_s`, `max_fails` | frozen node policy constants |
| `seed`, `method`, `note` | provenance (`method` = `time_gated` or `coverage`) |
