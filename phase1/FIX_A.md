# Fix A — replacing the hash chain with a depth-robust graph (DRG)

*Companion to [`FINDINGS.md`](FINDINGS.md). Phase 1 showed the thesis PoSpace scheme
labels a **hash chain** (a path graph) and therefore has **no space guarantee**: a
checkpoint time–memory trade-off lets a cheater store parts-per-million of the honest
tree and still answer every challenge, and no response-timeout δ separates honest from
cheater. Fix A replaces the chain's labelling graph with a **depth-robust graph** and
keeps everything else (Merkle commitment, challenge/verify shape). This writeup reports
what that buys, what it costs, and what still needs checking.*

Checklist for issue #7:

- [x] the construction (DRSample cite + parameters)
- [x] before/after attack result
- [x] whether a usable δ now exists
- [x] new plotting/proof/verify costs
- [x] honest caveats

---

## 0. Verdict

**Fix A restores a real space lower bound.** On the DRG-labelled scheme (**v3**), the
same retention/checkpoint attack that folded the chain now forces the cheater to
recompute a **back-cone that is a large fraction of the whole graph** — its cost climbs
toward O(N) at any storage saving, instead of the chain's O(k). As a result **a usable
timeout δ now exists**: at the thesis size (N = 3,355,443,200, ~200 GiB), *every* δ an
honest node can meet forces a cheater to store **≥ 50 % (δ=2) up to ~100 % (δ≥4)** of the
tree — versus **parts-per-million** under the chain. The honest node pays only modestly:
proofs stay in the **1.8–6.5 KiB** range, verify is **tens of µs**, and a native plotter
does 100 GiB in **~3–7 min**.

Two honest limits (§5): the guarantee we lean on is DRSample's **asymptotic**
depth-robustness, and an idealised **unlimited-core** attacker makes the *loosest* δ (5 s)
marginal. The verdict above uses the well-supported single-core (sequential) model.
Parameters must be signed off by a cryptographer/supervisor before any final thesis claim.

---

## 1. The construction (DRSample + parameters)

Fix A keeps the Merkle commitment and the challenge/verify shape of **v2** and changes
only *which graph is labelled*.

**Graph — DRSample** ([`drg.py`](drg.py); Alwen–Blocki–Harsha, *Practical Graphs for
Optimal Side-Channel Resistant Proofs of Space*, CCS 2017 **[ABH17]**). For each node
`i > 0`:

- the **path edge** `(i−1, i)` is always present; and
- each of the `(δ−1)` extra in-edges is a back-edge `(r, i)` sampled by the **bucket
  method**: draw `g ~ U[1, ⌊log₂ i⌋+1]`, then `d ~ U(2^{g−1}, 2^g]`, and set `r = i − d`.

The geometrically spread back-edges are what make the graph depth-robust. Crucially the
construction is **data-independent**: parents depend only on `(pk, i, δ)`, never on the
label values, with all randomness from `SHA-256(pk ‖ "drg" ‖ i ‖ edge_index)`. So the
**verifier reconstructs `parents(i)` itself**, and a run is reproducible bit-for-bit from
the same `pk`.

**Labelling & commitment** ([`pospace_drg.py`](pospace_drg.py)):

```
l_0 = H(pk ‖ 0)
l_i = H(pk ‖ i ‖ l_{p₁} ‖ l_{p₂} ‖ …)   for p in parents(i, pk, δ), in index order
```

The labels are Merkle-committed exactly as before. A **challenge `i` opens node `i` and
*all* its DRG parents**, each with its Merkle path; the verifier checks every path against
the root **and** the label equation `l_i = H(pk ‖ i ‖ ⧺ parent labels)`. Faking one label
now requires faking its whole (committed) parent set, so the only way to answer is to hold
or recompute the real labels — and recomputing is expensive *because* the graph is
depth-robust.

**Parameters swept:** in-degree **δ ∈ {2, 4, 8}**. Measured average in-degree
2.00 / 3.98 / 7.89 respectively ([`results/results_bench_v3.csv`](results/results_bench_v3.csv)).
`δ = 2` is the path graph plus one back-edge — the minimal DRG; `δ = 4, 8` add margin.

---

## 2. Before / after — the retention attack

[`attack_v3_retain.py`](attack_v3_retain.py) runs the **same attack class** that broke v2
against v3: the cheater plots the real tree once (it must publish the real root), keeps a
fraction `ρ = 1/s` of the labels plus the upper Merkle levels, and discards the rest. On a
challenge it must **materialise** the opened labels. Under the v2 chain a discarded label
is one chain step from a checkpoint, so recompute is **O(k)**. Under the DRG a discarded
label sits at the tip of a **back-cone** — follow parents back until everything bottoms out
at a retained label — and depth-robustness makes that back-cone large.

**Money table** — recompute hashes per challenge at **matched storage**, N = 2²²
([`results/fig_money.csv`](results/fig_money.csv), figure
[`results/fig_money.png`](results/fig_money.png)):

| storage kept | v2 chain — recompute | v3 DRG δ=2 | v3 DRG δ=4 | v3 DRG δ=8 |
|---|---|---|---|---|
| 0.15 % | 2 046 | **1 907 214** ⚠ | 2 399 299 ⚠ | 1 770 295 ⚠ |
| 2.34 % | 252 | 1 900 410 ⚠ | 2 028 144 ⚠ | 2 249 349 ⚠ |
| 9.38 % | 60 | 1 579 236 ⚠ | 2 044 203 ⚠ | 2 631 535 ⚠ |
| 37.5 % | — | 709 403 ⚠ | 1 442 073 ⚠ | 1 988 369 ⚠ |
| 75 % | — | 5 | 452 536 ⚠ | 1 274 605 ⚠ |

⚠ = `saturated`: the back-cone hit the measurement cap (~half the whole graph). The chain's
cost **falls** as it saves storage (that is the break); the DRG's cost **stays in the
1–3 million range** until the cheater keeps ~75 %+ of the labels. **v2 is O(k) and flat in
N; v3 is ≈O(N) at the same storage.** The cheap trade-off is gone.

---

## 3. Does a usable δ now exist? — yes

[`delta_separation_drg.py`](delta_separation_drg.py) extrapolates the measured back-cone
fraction `φ = rec_hashes / N` (verified ≈ flat across N = 2¹⁸→2²²) to the thesis size and
asks the money question: is there a timeout where an honest full-storage node passes but a
cheater storing a small fraction **fails**? The verdict uses the **sequential** model
(`t_seq = φ·N / rate`, rate = 20.36 MH/s single-core M4 — the same constant as
`FINDINGS.md`).

**Minimum storage a cheater is forced to keep** to answer within the timeout, RTT = 50 ms
([`results/fig_separation.csv`](results/fig_separation.csv) /
[`results/results_delta_separation.csv`](results/results_delta_separation.csv), figure
[`results/fig_separation.png`](results/fig_separation.png)):

| δ timeout | v2 chain (before) | v3 δ=2 | v3 δ=4 | v3 δ=8 | separation |
|---|---|---|---|---|---|
| 0.1 s | 5.7 × 10⁻⁶ | **0.75** | 1.00 | 1.00 | **PASS** |
| 0.5 s | 3.6 × 10⁻⁷ | 0.75 | 1.00 | 1.00 | **PASS** |
| 1 s | 1.8 × 10⁻⁷ | 0.75 | 1.00 | 1.00 | **PASS** |
| 2 s | 8.9 × 10⁻⁸ | 0.75 | 1.00 | 1.00 | **PASS** |
| 5 s | 4.5 × 10⁻⁸ | 0.75 | 1.00 | 1.00 | **PASS** |

Before Fix A, every feasible δ let a cheater through on **parts-per-million**
(`separation = NONE`). After Fix A, **every δ the honest node can meet forces the cheater
to store 50 %–100 % of the tree** — `PASS (>50 % forced)` at δ=2, `PASS (~100 % forced)` at
δ≥4, on every row. A usable δ exists across the whole feasible timeout range; the storage
fraction includes the retained upper Merkle levels, so δ=2's ρ=0.5 of *labels* is 0.75 of
*storage*.

---

## 4. New plotting / proof / verify costs

What the honest node pays, from [`results/results_bench_v3.csv`](results/results_bench_v3.csv)
and [`results/results_plot_extrap_v3.csv`](results/results_plot_extrap_v3.csv) (figure
[`results/fig_proof_verify.png`](results/fig_proof_verify.png)):

**Proof size** = `(1+δ)·(1+log₂N)·32` bytes (opens node + δ parents; measured == analytic):

| N | δ=2 | δ=4 | δ=8 |
|---|---|---|---|
| 2¹⁸ | 1.78 KiB | 2.97 KiB | 5.34 KiB |
| 2²² | 2.16 KiB | 3.59 KiB | 6.47 KiB |

vs v2's single ~1.4 KiB Merkle path — a small constant-factor growth (linear in δ).

**Verify time** (per challenge, checks 1+δ paths + the label equation): median
**17–68 µs** in Python (**2.7–9.7 µs** at the native rate), scaling with δ; still dwarfed by
the 50–300 ms network RTT.

**Plotting @ 100 GiB** (N = 3,355,443,200), replacing the old `rpos.py` "1h38m":

| δ | native floor | pure-Python |
|---|---|---|
| 2 | ~165 s | ~6 022 s |
| 4 | ~247 s | ~11 671 s |
| 8 | ~411 s | ~24 109 s |

Plotting is heavier than a chain (each label hashes its parents) but a native plotter still
does 100 GiB in **minutes**. **Caveat:** the old 1h38m baseline is itself inflated by the
`rpos.py` threading bug (`FINDINGS.md` Finding 0: `num_threads=4` emitted ~75 % duplicate
data) and must be **re-measured** before any speedup is claimed — do not compare against it
as-is. The Python column also excludes the random-I/O correction (§5).

---

## 5. Honest caveats

1. **The guarantee is asymptotic.** Single-layer DRSample gives depth-robustness
   ~Ω(N / log N) and cumulative memory complexity ~Ω(N² / log N) **[ABH17, ABP17]**. We
   **replicate** DRSample's construction; we do **not** re-prove its constants, and the
   separation in §3 rests on the *measured* back-cone fraction extrapolated to thesis N,
   not on a from-scratch pebbling proof.

2. **Parallel-floor sensitivity.** An attacker with unlimited perfect parallelism is bounded
   by the back-cone's **critical-path depth**, not its total size. The measured depths do
   **not** extrapolate cleanly (depth /(N/log N) is still shrinking at 2²² — a finite-size
   regime), so `delta_separation_drg.py` reports the parallel floor only as an
   *optimistic-for-the-attacker* sensitivity anchored to the Ω(N/log N) guarantee: theory
   anchor ≈ **5.15 s**. That makes the **loosest δ (5 s) marginal** under this idealised
   model. The §0/§3 verdict deliberately uses the well-supported **sequential** model; the
   parallel floor is a flagged sensitivity, not the basis of the claim.

3. **Stacked DRG as the stronger fallback.** If the single-layer margins are judged thin,
   the standard hardening is a **stacked DRG (SDR)** as used in Filecoin's proof of
   replication (Fisch, EUROCRYPT 2019 **[Fis19]**) or stacked expanders (Ren–Devadas, TCC
   2016 **[RD16]**) — multiple labelled layers, larger provable margin, at higher plotting
   and proof cost.

4. **Plotting is memory-hard, which is also a cost.** DRSample back-edges reach up to ~i/2,
   so once the label array exceeds RAM (crossover ≈ **12 GiB**), a label's parents become
   random SSD reads: **~7.35 %** of non-path parent reads fall beyond RAM at thesis N. This
   memory-hardness is a *feature* (it resists cheap plotting) but it means the honest plot
   time at 200 GiB is in the random-I/O regime, above the pure-hash floor in §4.

5. **Parameters need cryptographer/supervisor sign-off.** The in-degree δ, the target
   `(e, d)`-depth-robustness, and the resulting security margin must be sanity-checked
   against the published DRSample/SDR parameters **before any final thesis claim**. The
   numbers here demonstrate the *mechanism* works; they are not a substitute for that review.

---

## 6. Figures, reproduction, references

**Figures:** [`fig_money.png`](results/fig_money.png) (before/after recompute),
[`fig_separation.png`](results/fig_separation.png) (min-store vs δ),
[`fig_proof_verify.png`](results/fig_proof_verify.png) (costs),
[`fig_thesis_extrapolation.png`](results/fig_thesis_extrapolation.png).

**Reproduce** (standalone, fixed seeds; does **not** touch `rpos.py`):

```
cd phase1
python3 drg.py                    # DRSample DAG + reproducibility tests
python3 pospace_drg.py            # v3 round-trip + tamper tests
python3 attack_v3_retain.py       # -> results/results_v3_retain.csv (+ v2-vs-v3 money table)
python3 delta_separation_drg.py   # -> results/results_delta_separation.csv (separation verdict)
python3 bench_v3.py               # -> results/results_bench_v3.csv, results_plot_extrap_v3.csv
python3 plots.py                  # -> results/fig_*.png
```

**References**

- **[ABH17]** J. Alwen, J. Blocki, B. Harsha. *Practical Graphs for Optimal Side-Channel
  Resistant Proofs of Space.* ACM CCS 2017. *(DRSample — the construction in `drg.py`.)*
- **[ABP17]** J. Alwen, J. Blocki, K. Pietrzak. *Depth-Robust Graphs and Their Cumulative
  Memory Complexity.* EUROCRYPT 2017.
- **[Fis19]** B. Fisch. *Tight Proofs of Space and Replication.* EUROCRYPT 2019. *(Filecoin
  stacked-DRG PoRep — the §5 fallback.)*
- **[RD16]** L. Ren, S. Devadas. *Proof of Space from Stacked Expanders.* TCC 2016.
- **[DFKP15]** S. Dziembowski, S. Faust, V. Kolmogorov, K. Pietrzak. *Proofs of Space.*
  CRYPTO 2015. *(Why depth-robustness gives the space bound.)*
