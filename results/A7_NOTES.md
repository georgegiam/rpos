# A7 — Admission (join) cost: methodology notes (issue #38, Phase 6, examiner point (iii))

Reproducible trail for the A7 experiment. Numbers live in
[`A7_admission.csv`](A7_admission.csv) and [`fig_A7_admission.png`](fig_A7_admission.png); this
file records *how* they were produced and the honest caveats (CLAUDE.md §2 "measure, don't assert"
/ "flag, don't hide").

## What A7 measures
The **cost of joining the ring** — the resolver's *admission* path, which the thesis never measured
end-to-end (it timed only PoSpace plot initialisation in isolation). A joining node
(`node/pospace_admission.py`) must (1) **plot** the frozen v3 DRG scheme keyed by its own public
key (`plot_v3`), (2) **Merkle-commit** the labels (`commit_v3`), then (3) pass a **successor
challenge** — open a random leaf and all its DRG parents (`prove_v3`) and have the successor
`verify_v3` it within the δ=2 s timeout. A7 holds the ring at **N=8** and sweeps the **plot size**
over {2¹⁰, 2¹², 2¹⁴, 2¹⁶} leaves, with **δ=2** (the node default) as the headline plus a **δ∈{2,4,8}**
in-degree secondary axis. Issue #38's done-when: *a table of join time vs plot size* →
[`A7_admission.csv`](A7_admission.csv).

## Why a microbenchmark, not the Docker testbed
At these sizes a plot takes **~1.6 ms (2¹⁰) → ~105 ms (2¹⁶)** at δ=2. A real N=8 container ring would
bury that ~100 ms plot-size signal under **seconds** of container-startup / ring-convergence noise —
the plot-size dependence, which is the whole question, would be unmeasurable. A7 instead measures the
node's **exact** admission code deterministically, two ways that cross-check each other:

- **`source=component`** — directly times the very functions the node runs on admission
  (`plot_v3` / `commit_v3` / `prove_v3` / `verify_v3`, imported through `node/pospace_admission.py`,
  never copied — CLAUDE.md §2), over the **8 real ring keys** (`_pk_for(0..7)`) × 5 repeats. Gives the
  plot / commit / challenge **decomposition** the issue asks for.
- **`source=ring_inproc`** — builds a **real in-process 8-node ring** of the actual `PoSpaceNode`
  over `node/net.py` and times each node's genuine `create()` / `join()` (build plot → find_successor
  → successor challenge → verify → admit), × 3 repeats. This exercises the true admission path, not a
  reconstruction, and validates that it equals the sum of the component parts.

## Results (measured 2026-09-29, seed 20260919, N=8, δ=2 headline)
Full stats + run-to-run sd (and the δ∈{2,4,8} rows) in [`A7_admission.csv`](A7_admission.csv).

| plot size (leaves) | plot gen (ms) | Merkle commit (ms) | prove+verify (ms) | **admission total** (ms) | in-process ring join() (ms) | proof (B) |
|---|---|---|---|---|---|---|
| 2¹⁰ = 1 024  | 1.59   | 0.29  | 0.015 | **1.89**   | 2.26   | 1 056 |
| 2¹² = 4 096  | 6.54   | 1.14  | 0.018 | **7.70**   | 8.14   | 1 248 |
| 2¹⁴ = 16 384 | 26.01  | 4.51  | 0.020 | **30.55**  | 32.11  | 1 440 |
| 2¹⁶ = 65 536 | 106.20 | 18.32 | 0.023 | **124.54** | 129.55 | 1 632 |

(Component plotting throughput ≈ **617–644 klab/s** at δ=2, consistent with `phase1/bench_v3.py`.
Absolute times carry ~1–3 % wall-clock jitter run-to-run — see the `*_sd` columns; the trend is
what matters.)

**Headline.**
- **Join cost is dominated by plotting and scales linearly in the plot size (O(N)).** At δ=2, plot
  time is **1.59 → 6.54 → 26.01 → 106.20 ms** across the four sizes — a clean **×4.0–4.1 per 4× size
  step** (slope-1 on the log-log figure). This is expected: labelling the DRG is one SHA-256 per leaf.
- **Merkle commit is the second cost, ~15–17 % of plotting** (0.29 → 18.32 ms), and also O(N) (the
  binary tree is 2N−1 hashes). It is **independent of δ** (the tree is over the leaf labels, whatever
  their in-degree) — confirmed: commit is ~18 ms at 2¹⁶ for all of δ∈{2,4,8}.
- **The challenge (prove + verify) is negligible** — **tens of microseconds** at every size (prove
  ~4–22 µs, verify ~11–50 µs), because it opens only `1+δ` Merkle paths regardless of plot size. So
  the response fits the **δ=2 s admission timeout** (`PARAMETERS.md`) with **~5 orders of magnitude**
  of headroom at test scale; admission never false-rejects an honest joiner on time.
- **The in-process ring `join()` matches the component sum to within ~4 %** (e.g. 2¹⁶: ring 129.6 ms
  vs component 124.5 ms; 2¹⁰: 2.26 vs 1.89 ms — the wider gap at 2¹⁰ is the fixed `find_successor`
  constant being a larger fraction of a ~2 ms join). The small, roughly-constant excess is the
  `find_successor` lookup + in-process bus dispatch — i.e. the network/routing part of admission is a
  **small additive constant**, and plotting is what grows. This is the validation that the
  decomposition reflects the real admission path.

**Secondary axis — DRG in-degree δ (cost of the security parameter).** Larger δ buys depth-robustness
(Phase 1, `FIX_A.md`) but costs on every admission axis. At 2¹⁶: plot **106.2 / 214.8 / 438.7 ms** and
proof **1 632 / 2 720 / 4 896 B** for δ = **2 / 4 / 8**. Plotting throughput falls ≈ inversely with δ
(617 → 305 → 149 klab/s) because each label hashes ~δ parent labels; proof size grows ≈ linearly in δ
(each opened parent adds one Merkle path). Commit and the challenge wall-time are essentially
δ-independent.

**Examiner-facing takeaway:** admission cost is **plot-bound and linear in plot size**; the
verifiable-commitment and challenge steps are cheap (Merkle commit ~15 % of plotting; a proof is
tens of µs and 1–5 KiB), and the ring-routing part of a join is a small additive constant. Raising the
DRG in-degree δ trades proportional plot time and proof size for depth-robustness. At the test scale
(PLOT_N=1024, δ=2) a full join is **~2 ms**; the cost scales predictably with the operator's chosen
plot size.

## Native-rate floor (what an optimised C plotter would pay)
The pure-Python plot loop is the honest cost of *this* implementation. For an examiner-facing lower
bound, A7 also reports (column `plot_native_floor_ms`) the N label-hashes at the **measured native
single-core SHA-256 rate** (20.363 MH/s, `phase1/results/chainrate.csv`), weighted by the mean SHA
blocks per v3 label — the same convention as `phase1/bench_v3.py`. At 2¹⁶: native floor **3.22 / 4.83
/ 8.01 ms** for δ = 2 / 4 / 8, i.e. the Python plotter is **~33–55× a native one**. Thesis-scale
(200 GiB) plotting time is out of A7's scope and lives in `phase1/bench_v3.py`
(`results/results_plot_extrap_v3.csv`); A7 is about *admission at the ring's test scale*.

## The (small) new code — no frozen artifact touched
A7 adds only:
- **`experiments/a7_admission.py`** — the microbenchmark + analysis. It *imports* the admission
  functions the same way the node does (`from node.pospace_admission import …`) and reuses `_pk_for`,
  `PoSpaceNode`, `node/net.py`, and `phase1/drg.parents_all` for the native floor. It builds its own
  in-process rings (a small inline `_converge` mirroring `node/tests/util.run_protocol`).
- **`experiments/run_a7.sh`** — a thin reproducibility entrypoint (no Docker; documents params and
  invokes the python).

`rpos/rpos.py`, `node/chord.py`, `node/ledger.py`, `node/storage.py`, `phase1/pospace_drg.py`, and
`node/pospace_admission.py` are **byte-identical** (CLAUDE.md §2 freeze) — A7 reads them, never edits.

## Workload (frozen — `PARAMETERS.md`)
N_ring = **8** (the deterministic identities `_pk_for(0..7)`), δ = **2** headline / {2,4,8} secondary,
plot sizes {2¹⁰,2¹²,2¹⁴,2¹⁶}, seed **20260919** (per-node challenge RNG salted with the node id,
exactly as `node/pospace_admission.py`), 5 component repeats × 8 keys, 3 in-process-ring repeats,
30 prove/verify calls averaged per (key,repeat). Runs on the benchmark machine (Apple M4; CLAUDE.md
§5). δ (challenge timeout) = 2.0 s.

## Honest caveats (flag, don't hide — CLAUDE.md §2)
1. **The `component` admission total is local compute** (plot + commit + one prove + one verify); it
   omits the network. Over **real sockets** a join adds a couple of RPC round-trips (`find_successor`,
   `admit_peer`); the `ring_inproc` rows show this addition is a small (~sub-ms to few-ms) additive
   constant at test scale — well under the δ=2 s timeout — and does **not** change the O(N) plot-size
   trend. It is the reason the ring `join()` sits ~4 % above the component sum.
2. **In-process bus ≈ zero network**, so `ring_inproc` is a **lower bound** on socket admission
   latency (netem 5/50 ms links would add per-RPC delay). It is included to validate the *code path*
   and the *decomposition*, not as a socket-latency figure.
3. **These are test-scale plots** (≤ 2¹⁶ leaves ≈ 2 MiB of labels). The thesis production scale is
   N = 3.36×10⁹ (~200 GiB); its plotting time — and the out-of-RAM random-I/O regime — are measured
   and extrapolated separately in `phase1/bench_v3.py`, not here. A7's claim is only that admission
   cost is **plot-bound and linear in plot size**, which the sweep demonstrates directly.
4. **Founder vs joiner.** The ring seed is admitted "by fiat" (`create()`: plot + commit, no
   challenge); every other node is challenge-gated (`join()`). A7's headline "admission" = a
   **joiner** (the common case). The founder's `create()` time (plot + commit, no challenge) is
   recorded in each `ring_inproc` row's `note` and, as expected, ≈ the component plot + commit.

## How to reproduce
```
bash experiments/run_a7.sh                          # full sweep -> A7_admission.csv + fig + this NOTES' numbers
python3 experiments/a7_admission.py --component-only # faster: skip the in-process ring cross-check
python3 experiments/a7_admission.py --sizes 1024,4096 --repeats 1   # quick smoke
```
No Docker required. Deterministic under seed 20260919.

## Output schema — `A7_admission.csv`
One row per (`source`, `delta`, `size`):
`source, delta, log2_size, size, ring_n, repeats, t_plot_ms, t_plot_sd, t_commit_ms, t_commit_sd,
t_prove_ms, t_verify_ms, t_admission_ms, t_admission_sd, labels_per_s, plot_bytes, proof_bytes,
plot_native_floor_ms, note`. `source=component` fills the full decomposition (means over 8 keys × 5
repeats; `*_sd` are the standard deviations; `t_admission_ms = plot + commit + prove + verify`).
`source=ring_inproc` fills only `t_admission_ms`/`t_admission_sd` (the real `join()` wall-clock, mean ±
sd over the 7 joiners × 3 rings) with the founder `create()` time in `note`; its component columns are
blank by construction. Times are milliseconds.
