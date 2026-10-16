# B5 — Sybil vs PoSpace admission: methodology notes (issue #46, Phase 7, examiner point (ii))

Reproducible trail for the B5 attack experiment. Numbers live in
[`B5_sybil.csv`](B5_sybil.csv) and [`fig_B5_sybil.png`](fig_B5_sybil.png); this file records *how*
they are produced and the honest caveats (CLAUDE.md §2 "measure, don't assert" / "flag, don't hide").

## What B5 measures

For a fixed **storage budget**, how many v3-DRG PoSpace identities can an adversary create, and what
fraction of the **chunk space** does that buy — and does PoSpace actually **raise** the Sybil cost?
B0 (#41) frames B5 as a **budget axis, not an f-sweep**, tied to thesis Table 4.2
"Integrity/Fairness: Sybil (also Amortisation)".

The spine is one relation the codebase already fixes. A v3 plot is laid out as `bytearray(N*32)`
([`phase1/pospace_drg.py::plot_v3`](../phase1/pospace_drg.py)), so **one admitted identity costs
exactly `32 · N_plot` bytes of labels**. At the thesis plot `REAL_PLOT_N = 3,355,443,200` leaves
([`node/pospace_admission.py`](../node/pospace_admission.py)) that is **100 GiB of labels** (≈200 GiB
if the Merkle tree is retained). Admission binds `pk ↔ plot ↔ id` (`node_id = SHA-256(pk)`; the
challenger rejects any node where `node_id_from_pk(pk) ≠ peer_id`, and the plot is keyed by `pk`), and
**a plot cannot be amortised across identities** — `k` identities need `k` distinct `pk`s → `k`
distinct plots. So:

```
#identities = floor(storage_budget / (32 · N_plot))
```

### Headline finding — PoSpace raises the per-identity cost ~3.25 × 10⁹×

| | without admission | with v3-DRG PoSpace |
|---|---|---|
| cost of one identity | a keypair, **~33 B** | one plot, **100 GiB** (`32·REAL_PLOT_N`) |
| identities from a **1 PiB** budget | **3.4 × 10¹³** | **10 485** |
| chunk control vs a 10⁶-node ring | **→ 1.0** (full) | **0.031** (≥1-of-s) |

PoSpace raises the per-identity price by `(32·N_plot)/|pk| ≈ 3.25 × 10⁹`. Without admission any
budget mints effectively unbounded identities (`f → 1`, full chunk control); with admission a
realistic budget buys a **vanishing** fraction of an internet-scale ring. Storage is **linear in plot
size and independent of the DRG in-degree δ** (δ only raises plotting *time* and proof *size*,
FIX_A.md §4) — so the Sybil *storage* cost is fixed at `32·N_plot` for all δ.

> **This cost floor is CONDITIONAL — a measured gap, flagged not hidden (CLAUDE.md §2).** The
> `⌊budget / (32·N_plot)⌋` bound holds *only if the admission enforces a minimum plot size*. The
> reference admission ([`node/pospace_admission.py`](../node/pospace_admission.py), **frozen**) trusts
> the prover's **self-declared** `n`/`delta` (`challenge_peer` reads them from the commitment and never
> compares them to the ring's parameters or a floor), so Block 4's **min-plot-size gate fails**: an
> under-sized Sybil (`plot_n = 1024`, 32 KiB) is **admitted** into a ring whose honest nodes use a
> larger plot. Until a `n ≥ MIN_PLOT_N` (and `n`/`delta` = ring-agreed) check is added, a Sybil pays
> the *smallest accepted* plot, not 100 GiB. B5 reports the full-size cost as the *intended* bound and
> records the gap as a measured negative result — this is a concrete fix the thesis should recommend.

## Metric

* **Sybil yield** — `#identities = floor(budget / (32·N_plot))`, swept over a storage budget
  `{100 GiB … 100 PiB}` at the thesis plot; a native plot-*time* column (FIX_A §4: ~165 s/100 GiB at
  δ=2, native floor) shows the second cost axis. A test-plot row (`PLOT_N = 1024`, 32 KiB) shows the
  **emulation scale is deliberately not the security scale**.
  A **retention worst-case** row (`scheme=pospace_v3_retention`) prices an identity at
  `32·N_plot·ρ_min` with `ρ_min = 0.5` (the δ=2 labels-retention floor, FIX_A §3-4) as a sensitivity —
  v3 *defeats* retention at thesis N (recompute > timeout), so full retention is operative, but the
  worst case (loose extrapolation / parallel attacker) is reported, not hidden.
* **Chunk control** — for `m` Sybils **added** to a ring of `N_honest` honest nodes (`f = m/(m+N)`):
  **primary-arc** `m/(m+N)`, **forge / ≥1-of-s** `1−(1−f)^s` (B1's measured achievable bound), and
  **majority** `3f²−2f³` (s=3), all via [`b1_placement`](../experiments/b1_placement.py) so B5 is
  consistent with B1/B2. Analytic at `N_honest ∈ {32, 10³, 10⁶}`, **plus a measured N=32 structural
  anchor** over the real converged ring. These curves are the **random-placement (weak-adversary)
  LOWER bound**; a **targeted** anchor (`scheme=pospace_v3_targeted`) records the strong-adversary
  complement — grinding (B2) co-locates `⌈(s+1)/2⌉ = 2` plots on a chosen chunk's replica slots → that
  chunk captured (control 1.0) at **constant** cost, independent of budget.
* **PoSpace vs free** — identities and control with no admission (identity = a `|pk| = 33 B` keypair)
  vs with v3-DRG PoSpace (identity = 100 GiB plot), at a 10⁶-node reference ring — the cost PoSpace
  imposes.
* **Admission probe** — a real in-process PoSpace ring probed by **three gates**, each reported as
  `result = pass` (property holds) / `fail` (gap found): **(1) no-amortisation** — k distinct Sybils
  each build their own plot (k distinct roots); **(2) pk↔id binding** — a Sybil advertising *another*
  identity's commitment is **rejected** by `challenge_peer` (a real negative test on the gate's verdict,
  not the tautology `node_id == H(pk)`); **(3) min-plot-size** — an under-sized Sybil is (incorrectly)
  admitted, exposing the gap above.

## Results (thesis plot 100 GiB/identity, s=3, seed 20260919)

### Block 1 — Sybil yield: identities per storage budget (thesis plot)

| budget | identities (PoSpace v3) | plot time / identity (native, δ=2) |
|---:|---:|---:|
| 100 GiB | **1** | ~2.8 min |
| 1 TiB | 10 | ~2.8 min |
| 10 TiB | 102 | ~2.8 min |
| 100 TiB | 1 024 | ~2.8 min |
| 1 PiB | 10 485 | ~2.8 min |
| 10 PiB | 104 857 | ~2.8 min |
| 100 PiB | 1 048 576 | ~2.8 min |

(Test plot `2^10` = 32 KiB: 1 GiB mints **32 768** identities — trivially Sybil-able; the emulation
scale is not the security scale.)

### Block 2 — chunk control vs budget

Analytic forge (≥1-of-s) control across the budget sweep, by honest ring size:

| N_honest | 100 GiB | 100 PiB |
|---:|---:|---:|
| 32 | 0.0882 | 1.0000 |
| 1 000 | 0.0030 | 1.0000 |
| 1 000 000 | 0.0000 | 0.8837 |

A bigger ring needs exponentially more budget to control — the Sybil-resistance curve. **Measured
N=32 structural anchor** (m Sybils added to the real 32-node ring, random `_pk_for` placement, 1000
served chunks):

| m (identities) | budget | f | forge (≥1-of-s) | majority |
|---:|---:|---:|---:|---:|
| 1 | 100 GiB | 0.030 | 0.170 | 0.000 |
| 3 | 300 GiB | 0.086 | 0.289 | 0.023 |
| 10 | 1000 GiB | 0.238 | 0.635 | 0.137 |
| 16 | 1.56 TiB | 0.333 | 0.729 | 0.252 |
| 31 | 3.03 TiB | 0.492 | 0.858 | 0.455 |

The measured anchor tracks the i.i.d. analytic bound (self-test (d): within B1's finite-ring
tolerance; it sits *slightly above* the bound because the realised placement on a small ring is a
little lumpier than i.i.d. — reported, not hidden). These are the **random-placement lower bound**;
the **targeted** anchor row shows **2 plots** capture a chosen chunk's majority (control 1.0) at
constant cost regardless of budget (grinding — B2).

### Block 3 — PoSpace vs free: the cost PoSpace imposes (N_honest = 10⁶ reference)

| budget | free: identities | free: control | PoSpace: identities | PoSpace: control |
|---:|---:|---:|---:|---:|
| 100 GiB | 3.25 × 10⁹ | 1.000 | 1 | 0.0000 |
| 1 PiB | 3.41 × 10¹³ | 1.000 | 10 485 | 0.0308 |
| 100 PiB | 3.41 × 10¹⁵ | 1.000 | 1 048 576 | 0.8837 |

Without admission every budget already owns the ring; with PoSpace even **1 PiB** controls ~3% and
reaching majority of a million-node ring needs the whole plot store of an internet backbone.

### Block 4 — in-process admission probe (`source=admission_inproc`): three measured gates

On a real 8-node in-process PoSpace ring (the A7 `create()`/`join()` pattern):

| gate | `result` | what it measures |
|---|---|---|
| **no-amortisation** | **pass** | 3/3 distinct Sybils admitted, **3 distinct plot roots** — one plot per identity (k ids need k plots). |
| **pk↔id binding** | **pass** | a Sybil whose `pospace_commitment` advertises **node 0's** `(pk, root)` is **rejected** by `challenge_peer` (`node_id_from_pk(pk) ≠ peer_id`) — plot reuse across ids is blocked. A real negative test on the gate's verdict. |
| **min-plot-size** | **fail** | an under-sized Sybil (`plot_n = 1024`) is **admitted** into a `plot_n = 4096` ring — the frozen admission enforces **no minimum** and trusts self-declared `n`/`delta`. **A measured gap** (see the CONDITIONAL caveat above). |

No-amortisation + binding are the mechanisms that make the storage axis real (a plot pins exactly one
identity; a pk cannot borrow another's plot). The min-plot-size **fail** is the honest counterweight:
the cost floor is only as strong as a check the reference code does not yet implement. **Caveat
(predictable single-leaf challenge):** at this test scale the challenge opens one leaf with a
deterministically-seeded index and recompute is trivial, so "admitted" here is *not itself* proof of
dedicated storage — the storage lower bound rests on the thesis-scale retention analysis (FIX_A /
[`results_v3_retain.csv`](../phase1/results/results_v3_retain.csv)), not on this demo. Fresh
per-challenge randomness and `k>1` openings (pass prob `q^k`) are the production hardening.

### Control

Zero budget → **0** Sybils → `structural_capture_fraction([]) = 0.0`: Sybil power is
**adversary-caused**, and it is a **protocol/design property** (admission binds `pk↔plot↔id`),
**not `chord.py` reference-implementation fragility** (the epic's cross-cutting requirement — B5
touches no live ring maintenance).

## The new driver (no frozen edit — CLAUDE.md §2)

* [`experiments/b5_sybil.py`](../experiments/b5_sybil.py) — the analyzer + `--self-test`.
  **Imports/reads only**: reuses [`experiments/b1_placement.py`](../experiments/b1_placement.py)
  (`build_ring`, `capture_threshold`, `effective_bound`, `analytic_bound`,
  `structural_capture_fraction`, `load_served_domains`) and [`node/ids.py`](../node/ids.py); the
  in-process demo lazily imports `PoSpaceNode`/`Network`/`_pk_for` (skipped with a clear note if
  dnspython is absent, so the cost analysis runs anywhere). Writes `results/B5_sybil.csv` +
  `results/fig_B5_sybil.png`.
* [`experiments/run_b5.sh`](../experiments/run_b5.sh) — thin A7/B2-style wrapper (self-test →
  analysis, **no Docker**).

`rpos/rpos.py`, `node/chord.py`, `node/storage.py`, `node/ledger.py`, `node/pospace_admission.py`,
`node/net.py`, `phase1/pospace_drg.py`, `phase1/drg.py` and `experiments/b1_placement.py` are
byte-identical.

## Workload (frozen — PARAMETERS.md)

Thesis plot `REAL_PLOT_N = 3,355,443,200` leaves (100 GiB labels/identity); s=3; budget sweep
{100 GiB, 1 TiB, 10 TiB, 100 TiB, 1 PiB, 10 PiB, 100 PiB}; honest ring sizes {32, 10³, 10⁶};
measured anchor m ∈ {0,1,2,3,6,10,16,24,31} Sybils added to N=32; retention ρ_min = 0.5 (FIX_A δ=2);
free-identity size |pk| = 33 B; native plot floor 165/247/411 s per 100 GiB at δ=2/4/8 (FIX_A §4);
admission probe N=8 honest ring at plot 2^12 + 3 Sybils + a binding spoof + an under-sized (2^10)
Sybil; seed 20260919.

## Honest caveats (flag, don't hide — CLAUDE.md §2)

1. **The cost floor is CONDITIONAL on a minimum-plot-size check the reference admission lacks.**
   `challenge_peer` trusts the prover's self-declared `n`/`delta`, so an under-sized Sybil is admitted
   (Block 4 min-plot-size gate = **fail**). `⌊budget / (32·N_plot)⌋` is the cost *once* a
   `n ≥ MIN_PLOT_N` (and `n`/`delta` = ring-agreed) check exists — a fix the thesis should recommend.
   Without it a Sybil pays the smallest accepted plot. Measured, not asserted.
2. **Storage is δ-independent.** δ only raises plotting *time* (165→411 s/100 GiB) and proof size; the
   Sybil *storage* cost is fixed at `32·N_plot` for all δ. The δ=2 plot-time column is informational.
3. **Retention time-memory trade-off.** Under the v3 DRG a cheater who discards labels must recompute
   a large back-cone on challenge; FIX_A §3-4 + [`results_v3_retain.csv`](../phase1/results/results_v3_retain.csv)
   show that at thesis N even retaining ρ=0.75 of storage exceeds the timeout → **v3 defeats partial
   storage**, so full retention is the operative per-identity cost. The CSV still emits a
   `pospace_v3_retention` **worst-case** row at `ρ_min = 0.5` of labels (≈2× yield) in case the
   thesis-scale back-cone extrapolation is loose or a parallel attacker is assumed (FIX_A's open caveat).
4. **100 GiB vs 200 GiB.** We price an identity at the **labels-only floor** (100 GiB = `32·N`); the
   full Merkle tree adds up to another 100 GiB (≈200 GiB). Using the floor is the **conservative**
   (attacker-favouring) choice — the real full-retention cost is ≥ this.
5. **Chunk-control curves are the RANDOM-placement (weak-adversary) LOWER bound.** The analytic and
   measured-N=32 curves assume uniform Sybil placement. A **targeted** adversary (grinding, B2) captures
   a *chosen* chunk with a constant `⌈(s+1)/2⌉ = 2` plots regardless of budget — the
   `pospace_v3_targeted` row. Placement is free (B2), identities are costly (B5); the two compose.
6. **Security lives at the thesis plot, not emulation.** At `PLOT_N = 1024` (32 KiB) Sybil is trivial
   **by design** (the emulation scale is chosen for testbed speed); the defensible numbers use
   `REAL_PLOT_N`. The CSV carries one explicit `pospace_v3_testplot` row to make this unmistakable.
7. **The admission probe uses test plots and a predictable single-leaf challenge.** It proves the
   *binding* + *no-amortisation* gates and *exposes* the *min-plot-size* gap, **not** the 100 GiB cost
   (A7 + the FIX_A plot-time table) and **not** dedicated-storage enforcement — at this scale one
   deterministically-indexed leaf is opened and recompute is trivial, so "admitted" is not itself proof
   of storage; that lower bound is the thesis-scale retention result. Fresh per-challenge randomness and
   `k>1` openings (pass prob `q^k`) are the production hardening.
8. **Large-N chunk control is the i.i.d. analytic limit.** The measured N=32 structural rows are the
   anchor; the {10³, 10⁶} curves are the bound `1−(1−f)^s` / `3f²−2f³`, not re-measured at scale (the
   emulation ceiling is N=32). The measured anchor sits slightly above the bound (finite-ring lumpiness).
9. **"Free" identity size = `|pk| = 33 B`.** A no-admission identity still needs a keypair; we charge
   its 33-byte public key. This is the most generous accounting for the attacker (identities could be
   even cheaper), so the ~3.25 × 10⁹× cost ratio is a lower bound on what PoSpace imposes.

## How to reproduce

```bash
python3 experiments/b5_sybil.py --self-test     # deterministic checks (incl. the admission probe)
python3 experiments/b5_sybil.py --self-test --require-demo   # CI/security gate: a SKIP counts as FAIL
bash experiments/run_b5.sh                       # self-test, then full analysis -> CSV + PNG
python3 experiments/b5_sybil.py --no-demo --no-plot   # cost analysis only (no dnspython/matplotlib)
```

Run under the 3.11 experiment env (dnspython + matplotlib). Seed 20260919 → identical identity
counts, control fractions, and the same admission-probe verdicts (no-amortisation pass, binding pass,
min-plot-size fail). The import guard is narrowed to `ImportError`/`ModuleNotFoundError`, so a genuine
error surfaces instead of masquerading as a skip; `main()` exits non-zero if the probe ran and did not
match the expected verdicts, and `--require-demo` additionally fails a skip.

## Output schema (`B5_sybil.csv`)

| column | meaning |
|---|---|
| `metric` | `sybil_yield` / `chunk_control` / `pospace_vs_free` / `admission_demo` / `control` |
| `source` | `analytic` / `real_ring` (measured structural/targeted) / `admission_inproc` (probe) |
| `scheme` | `pospace_v3` / `pospace_v3_testplot` / `pospace_v3_retention` (worst-case) / `pospace_v3_targeted` (strong adversary) / `none` (no admission) |
| `plot_n`, `plot_bytes`, `plot_h` | plot size (leaves) and bytes/identity (`32·N_plot`; retention = `×ρ_min`; `scheme=none` this is `|pk|`) |
| `storage_budget_bytes`, `storage_budget_h` | the adversary's storage budget (bytes / human) |
| `N_honest` | honest ring size the Sybils are added to |
| `identities` | identities the budget buys = `floor(budget / plot_bytes)` (the headline) |
| `f` | adversary fraction `m/(m+N_honest)` |
| `control_primary`, `control_forge_1ofs`, `control_majority` | chunk-space fractions controlled (primary-arc, ≥1-of-s, majority); random placement = lower bound |
| `plot_seconds_native` | native single-core plot time per identity (FIX_A §4, δ-dependent) |
| `result` | admission-probe verdict: `pass` (property holds) / `fail` (gap found) / `skipped`; blank for non-probe rows |
| `note` | per-row detail / caveat |
