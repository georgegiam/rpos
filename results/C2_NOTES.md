# C2 — response timeout δ under realistic network jitter: methodology notes (issue #51, Phase 8, examiner point (i))

Reproducible trail for the δ-separation-under-jitter experiment. Numbers live in
[`C2_delta_jitter.csv`](C2_delta_jitter.csv) and [`fig_C2_roc.png`](fig_C2_roc.png); this file
records *how* they are produced and the honest caveats (CLAUDE.md §2 "measure, don't assert" /
"flag, don't hide"). Driver: [`experiments/c2_delta_jitter.py`](../experiments/c2_delta_jitter.py)
(+ [`run_c2.sh`](../experiments/run_c2.sh)).

## What C2 measures

C1 (#50) produced the definitive storage→recompute-time trade-off for the frozen v3 DRG scheme, but
as a **pure compute** model — δ was a flat threshold with no network. C2 adds the missing piece,
**realistic network jitter**, and answers the money question literally:

> **"What δ separates honest from cheater *without rejecting honest provers* under real network
> conditions?"**

The single threshold becomes two measurable error rates:

- **false-reject** — P(an **honest** prover's challenge-response arrives after δ). An honest prover
  is network-bound: one challenge→proof round trip plus a few-µs Merkle proof. Under jitter its
  response time is a *distribution*; a too-tight δ rejects honest nodes.
- **false-accept** — P(a **cheater** keeping storage fraction ρ answers within δ). A cheater is
  compute-bound: it must recompute the DRG back-cone (seconds, from C1). A too-loose δ accepts it.

### Headline finding

**δ ≤ 2 s cleanly separates honest from cheater under realistic jitter.** Honest provers stay
network-bound (cross-region p99 response **146.5 ms** at σ=20 ms), so **false-reject ≈ 0 for every δ
in {1, 2, 3, 5, 10} s**; a cheater keeping < 50 % labels recomputes ≥ 13 s (C1), so **false-accept =
0 for δ ≤ 2 s** (and up to δ=10 s at 25 % keep). The loosest δ = 5 s is **marginal only against the
unlimited-core parallel floor ≈ 5.15 s** (Phase 1 FIX_A §5) — a flagged sensitivity, not the verdict
basis. **Recommend δ ≤ 2 s.**

| δ_g=2, cross, σ=20 ms | δ=1 s | δ=2 s | δ=3 s | δ=5 s | δ=10 s |
|---|---|---|---|---|---|
| honest false-reject | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| cheater FA, keep 50 % (t_rec≈0 s) | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| cheater FA, keep 25 % (t_rec=13.0 s) | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| cheater FA, keep 10 % (t_rec=60.8 s) | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| cheater FA, keep 5 % (t_rec=80.4 s) | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

A cheater keeping **50 %** labels (≈75 % of the tree) has ~zero recompute, so timing **cannot**
distinguish it from honest at any δ — but that is not a storage-saving attack: it has paid almost the
full honest cost. The interesting adversary discards storage, and the ROC (fig panel A) shows every
such cheater (≤25 % keep) pinned to the **bottom-left** (FA=0, FR=0) at the operating δ.

**A concrete loosening risk:** at **δ_g=8, keep 75 % (t_rec=6.83 s)**, false-accept jumps from 0 at
δ≤5 s to **1.00 at δ=10 s** — a direct demonstration that the largest δ in the grid is exploitable.
This is the empirical face of the parallel-floor caveat and the reason to **prefer δ ≤ 2 s**.

## Why a microbenchmark, not the Docker testbed

Like A7/B2/B5/C1, C2 needs no Docker. The honest challenge-response cost is a property of the PoSpace
**plot graph** (the frozen `prove_v3`/`verify_v3`), measured here in-process over real challenges; the
netem delays enter the model as **parameters** (the issue specifies "fixed base RTT … + Gaussian
jitter", not a live capture). A containerised run would only measure the **test-scale** admission
path (`PLOT_N=1024`, test δ=2 s) whose timing says nothing about the **thesis-scale** δ this
experiment is about — the two are distinct and must not be conflated (PARAMETERS.md, response-timeout
caveat). The cheater curve is the committed thesis-scale extrapolation from C1.

## Metric

Per (rtt_tier, DRG in-degree δ_g, jitter σ, response timeout δ), and per cheater storage fraction ρ:

- **honest response** `T_h = base_rtt + c_h + J`, `J ~ N(0, σ)`, `c_h` = honest proof compute (below).
  `false_reject = P(T_h > δ) = 1 − Φ((δ − base_rtt − c_h)/σ)`. Columns `honest_p50_resp_ms`,
  `honest_p99_resp_ms`, `false_reject_rate`.
- **cheater response** `T_c = base_rtt + t_rec(ρ) + J`. `false_accept = P(T_c ≤ δ) = Φ((δ − base_rtt
  − t_rec)/σ)`. Columns `cheater_recompute_s`, `cheater_p50_resp_s`, `false_accept_rate`.
- `par_floor_s` — C1's unlimited-core critical-path floor ≈ 5.15 s, carried on every cheater row.

Rates are the **exact Gaussian CDF** (`statistics.NormalDist`, deterministic → byte-identical
re-runs); a seeded Monte-Carlo draw (seed 20260919, 100 000 samples) cross-checks them in
`--self-test` (agreement < 0.01).

## Jitter model (frozen — PARAMETERS.md / issue #51)

- **base RTT = 2 × one-way netem delay** (a challenge-response is a round trip): intra-region
  2×5 ms = **10 ms**, cross-region 2×50 ms = **100 ms**.
- **Gaussian jitter** `J ~ N(0, σ)`, σ ∈ {5, 10, 20} ms, one draw per response.
- **response-timeout grid** δ ∈ {1, 2, 3, 5, 10} s; **DRG in-degree** δ_g ∈ {2, 4, 8} (headline 2).

## Honest compute: real anchor → deterministic model term

The honest proof cost `c_h` enters the rate model as a **deterministic thesis-scale analytic term**,
with a **real in-process measurement** reported as the "measure, don't assert" anchor (the same split
C1 uses: a live wall-clock anchor validates a modelled, reproducible number):

- **real anchor (measured, stdout)** — `plot_v3` a 2^14 plot once per δ_g, then time
  `prove_v3`+`verify_v3` over 200 real challenges; median ≈ **20 µs** (δ_g=2), ~35 µs (δ_g=4),
  ~61 µs (δ_g=8). Confirms the honest proof is real and ~µs. (Live timing → not written to the CSV.)
- **model c_h (deterministic, in the CSV)** — `(1 + avg_indeg(δ_g)) · (log₂N_thesis + 1)` hashes /
  20.36 MH/s (Merkle paths grow with log₂N = 32): **4.9 / 8.1 / 14.4 µs** for δ_g = 2 / 4 / 8. This is
  the correct quantity for a thesis-N δ claim and keeps the CSV byte-reproducible.

Both are ~µs — **three to four orders of magnitude below the base RTT** — so honest response is
network-dominated and `c_h` barely moves the result (the real anchor and the analytic term agree to
within an order of magnitude, as expected). Using the smaller analytic term in the model understates
honest latency by ~15 µs on a ≥100 ms base — negligible, and false-reject stays 0 either way.

## The new driver — no frozen artifact touched

- New: `experiments/c2_delta_jitter.py`, `experiments/run_c2.sh`, this file.
- Imported, never copied (CLAUDE.md §2): `phase1/pospace_drg.py` (`plot_v3`/`commit_v3`/`prove_v3`/
  `verify_v3`), `phase1/delta_separation_drg.py` (`avg_indegree`), the shared chain-rate loader over
  `phase1/results/chainrate.csv`.
- Read only: `results/C1_retention_attack.csv` (cheater curve), `node/pospace_admission.py`
  (`REAL_PLOT_N`). `rpos/rpos.py`, all of `phase1/*` and `node/*` stay byte-identical.

## Honest caveats (flag, don't hide — CLAUDE.md §2)

1. **RTT = 2 × one-way.** Issue #51 calls the 5/50 ms figures "base RTT"; PARAMETERS.md defines them
   as **one-way** netem delays. The physically-correct round trip is 2× (10/100 ms), used here. The
   factor does not change any conclusion — honest base stays ~10×–100× below the smallest δ.
2. **Parallel attacker.** The verdict uses the well-supported **sequential** recompute model. An
   unlimited-core attacker is bounded below by the back-cone **critical-path depth**, a floor ≈
   (N/log₂N)/rate ≈ **5.15 s** (`par_floor_s`), which makes δ = 5 s **marginal** and is why we prefer
   δ ≤ 2 s. Carried from C1 / FIX_A §5 — a flagged sensitivity, not the verdict basis.
3. **Inherited C1 extrapolation.** `t_rec(ρ)` is C1's thesis-scale φ·N/rate, with φ taken flat ~800×
   beyond the measured 2^18–2^22 range (DRSample's asymptotic depth-robustness, not a re-proof). C2
   adds no new extrapolation; it reads C1's committed deliverable.
4. **DRG in-degree δ_g awaits sign-off.** Choice of δ_g, target depth-robustness, and whether a
   stacked DRG is needed remain open for the cryptographer/supervisor (CLAUDE.md, Phase 1 "Open").
   C2 reports all of {2, 4, 8}; the headline is the node default δ_g = 2.
5. **Jitter is Gaussian and additive.** Real network delay is heavier-tailed (occasional retransmits,
   queueing). A one-sided heavy tail would only raise honest false-reject at *very* tight δ (< base
   RTT); at δ ≥ 1 s the ~1-second margin absorbs any realistic tail, so the ≈0 false-reject result is
   robust. Modelled, not captured live (see "Why a microbenchmark").

## How to reproduce

```bash
bash experiments/run_c1.sh          # dependency: writes results/C1_retention_attack.csv
bash experiments/run_c2.sh          # self-test, then CSV + ROC figure
# or directly:
python3 experiments/c2_delta_jitter.py --self-test
python3 experiments/c2_delta_jitter.py
```

Deterministic (fixed seed 20260919, exact Gaussian CDF) → re-runs are byte-identical.

## Output schema (`C2_delta_jitter.csv`)

| column | meaning |
|---|---|
| `role` | `honest` or `cheater` |
| `rtt_tier` | `intra` (10 ms) or `cross` (100 ms) base RTT |
| `base_rtt_ms` | base round-trip time (2 × one-way netem) |
| `drg_indegree` | DRG in-degree δ_g ∈ {2,4,8} |
| `sigma_ms` | Gaussian jitter σ (ms) |
| `resp_delta_s` | response timeout δ (s) |
| `storage_frac_pct` | cheater: % of plot **labels** kept (blank for honest) |
| `honest_compute_ms` | honest proof compute c_h (deterministic thesis-analytic; real prove+verify anchor printed to stdout) |
| `honest_p50_resp_ms`, `honest_p99_resp_ms` | honest response percentiles under jitter |
| `cheater_recompute_s` | t_rec(ρ) from C1 extrapolated (thesis N) |
| `cheater_p50_resp_s` | base_rtt + t_rec (median) |
| `false_reject_rate` | honest: P(T_h > δ) |
| `false_accept_rate` | cheater: P(T_c ≤ δ) |
| `par_floor_s` | unlimited-core parallel floor ≈ 5.15 s (cheater rows) |
| `mc_samples` | Monte-Carlo cross-check size (self-test) |
| `method` | rate method (`normal_cdf`) |
| `note` | provenance |
