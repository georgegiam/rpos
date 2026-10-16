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

## Metric

* **Sybil yield** — `#identities = floor(budget / (32·N_plot))`, swept over a storage budget
  `{100 GiB … 100 PiB}` at the thesis plot; a native plot-*time* column (FIX_A §4: ~165 s/100 GiB at
  δ=2, native floor) shows the second cost axis. A test-plot row (`PLOT_N = 1024`, 32 KiB) shows the
  **emulation scale is deliberately not the security scale**.
* **Chunk control** — for `m` Sybils **added** to a ring of `N_honest` honest nodes (`f = m/(m+N)`):
  **primary-arc** `m/(m+N)`, **forge / ≥1-of-s** `1−(1−f)^s` (B1's measured achievable bound), and
  **majority** `3f²−2f³` (s=3), all via [`b1_placement`](../experiments/b1_placement.py) so B5 is
  consistent with B1/B2. Analytic at `N_honest ∈ {32, 10³, 10⁶}`, **plus a measured N=32 structural
  anchor** over the real converged ring (random Sybil placement, `source=real_ring`).
* **PoSpace vs free** — identities and control with no admission (identity = a `|pk| = 33 B` keypair)
  vs with v3-DRG PoSpace (identity = 100 GiB plot), at a 10⁶-node reference ring — the cost PoSpace
  imposes.
* **Admission demo** — a real in-process PoSpace ring where **k distinct Sybils are admitted** (genuine
  v3 plot + successor challenge each) and each built its **own** plot (k distinct commitment roots),
  with the `pk↔id` binding blocking plot reuse — the **no-amortisation** property.

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
little lumpier than i.i.d. — reported, not hidden).

### Block 3 — PoSpace vs free: the cost PoSpace imposes (N_honest = 10⁶ reference)

| budget | free: identities | free: control | PoSpace: identities | PoSpace: control |
|---:|---:|---:|---:|---:|
| 100 GiB | 3.25 × 10⁹ | 1.000 | 1 | 0.0000 |
| 1 PiB | 3.41 × 10¹³ | 1.000 | 10 485 | 0.0308 |
| 100 PiB | 3.41 × 10¹⁵ | 1.000 | 1 048 576 | 0.8837 |

Without admission every budget already owns the ring; with PoSpace even **1 PiB** controls ~3% and
reaching majority of a million-node ring needs the whole plot store of an internet backbone.

### Block 4 — in-process admission demo (`source=admission_inproc`): one plot per identity

On a real 8-node in-process PoSpace ring (the A7 `create()`/`join()` pattern), **3/3 distinct Sybils
were admitted** — each built a genuine v3 DRG plot and passed its successor's challenge — with **3
distinct commitment roots** and **`binding_ok = True`** (each Sybil's `node_id == node_id_from_pk(pk)`,
so no plot's `pk` can masquerade as another id). This is the **no-amortisation** mechanism behind the
linear cost: the storage axis is real because a plot pins exactly one identity.

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
measured anchor m ∈ {0,1,2,3,6,10,16,24,31} Sybils added to N=32; free-identity size |pk| = 33 B;
native plot floor 165/247/411 s per 100 GiB at δ=2/4/8 (FIX_A §4); in-process demo N=8 honest + 3
Sybils at test plot 2^10; seed 20260919.

## Honest caveats (flag, don't hide — CLAUDE.md §2)

1. **Storage is δ-independent.** δ only raises plotting *time* (165→411 s/100 GiB) and proof size; the
   Sybil *storage* cost is fixed at `32·N_plot` for all δ. The δ=2 plot-time column is informational.
2. **100 GiB vs 200 GiB.** We price an identity at the **labels-only floor** (100 GiB = `32·N`); the
   full Merkle tree adds up to another 100 GiB (≈200 GiB), and FIX_A's retention analysis shows a
   cheater must hold ≥50–100% of the tree. Using the floor is the **conservative** (attacker-favouring)
   choice — the real cost is ≥ this.
3. **Placement is free (B2), identities are costly (B5).** B5 measures the *count* cost of identities;
   B2 already showed `id = H(pk)` grinding puts those identities *anywhere* for ~free. The two compose:
   a Sybil adversary pays the B5 plot cost to mint identities, then places them for free (B2).
4. **Security lives at the thesis plot, not emulation.** At `PLOT_N = 1024` (32 KiB) Sybil is trivial
   **by design** (the emulation scale is chosen for testbed speed); the defensible numbers use
   `REAL_PLOT_N`. The CSV carries one explicit `pospace_v3_testplot` row to make this unmistakable.
5. **The demo uses a 2^10 test plot.** It proves the *admission + no-amortisation* chain (k distinct
   plots for k ids, pk↔id binding), **not** the 100 GiB cost — that cost (minutes native) is quantified
   by A7 and the FIX_A plot-time table, and is the true per-identity price of every Block-1/3 row.
6. **Large-N chunk control is the i.i.d. analytic limit.** The measured N=32 structural rows are the
   anchor; the {10³, 10⁶} curves are the bound `1−(1−f)^s` / `3f²−2f³`, not re-measured at scale (the
   emulation ceiling is N=32). The measured anchor sits slightly above the bound (finite-ring lumpiness).
7. **"Free" identity size = `|pk| = 33 B`.** A no-admission identity still needs a keypair; we charge
   its 33-byte public key. This is the most generous accounting for the attacker (identities could be
   even cheaper), so the ~3.25 × 10⁹× cost ratio is a lower bound on what PoSpace imposes.

## How to reproduce

```bash
python3 experiments/b5_sybil.py --self-test     # deterministic checks (incl. the in-process demo)
bash experiments/run_b5.sh                       # self-test, then full analysis -> CSV + PNG
python3 experiments/b5_sybil.py --no-demo --no-plot   # cost analysis only (no dnspython/matplotlib)
```

Run under the 3.11 experiment env (dnspython + matplotlib). Seed 20260919 → identical identity
counts, control fractions, and the same 3 admitted Sybils.

## Output schema (`B5_sybil.csv`)

| column | meaning |
|---|---|
| `metric` | `sybil_yield` / `chunk_control` / `pospace_vs_free` / `admission_demo` / `control` |
| `source` | `analytic` / `real_ring` (measured structural) / `admission_inproc` (in-process demo) |
| `scheme` | `pospace_v3` / `pospace_v3_testplot` / `none` (no admission) |
| `plot_n`, `plot_bytes`, `plot_h` | plot size (leaves) and bytes/identity (`32·N_plot`; for `scheme=none` this is `|pk|`) |
| `storage_budget_bytes`, `storage_budget_h` | the adversary's storage budget (bytes / human) |
| `N_honest` | honest ring size the Sybils are added to |
| `identities` | identities the budget buys = `floor(budget / plot_bytes)` (the headline) |
| `f` | adversary fraction `m/(m+N_honest)` |
| `control_primary`, `control_forge_1ofs`, `control_majority` | chunk-space fractions controlled (primary-arc, ≥1-of-s, majority) |
| `plot_seconds_native` | native single-core plot time per identity (FIX_A §4, δ-dependent) |
| `note` | per-row detail / caveat |
