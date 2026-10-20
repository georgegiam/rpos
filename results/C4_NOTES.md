# C4 — proof size & prover/verifier time vs Chia: methodology notes (issue #53, Phase 8, examiner point (i))

Reproducible trail for the "what are the concrete costs of each scheme?" experiment. Numbers live in
[`C4_proof_metrics.csv`](C4_proof_metrics.csv) and [`fig_C4_proof_metrics.png`](fig_C4_proof_metrics.png);
this file records *how* they are produced and the honest caveats (CLAUDE.md §2 "measure, don't assert" /
"flag, don't hide"). Driver: [`experiments/c4_proof_metrics.py`](../experiments/c4_proof_metrics.py)
(+ [`run_c4.sh`](../experiments/run_c4.sh)). Reuses the A7 admission harness (#38) and the frozen v3
DRG scheme; pairs the measured proposed-scheme costs with cited Chia k=32 numbers.

## What C4 measures

C1–C3 characterised the *security* of the proposed v3 scheme (retention trade-off, δ separation,
detection). C4 supplies the other half of the examiner's comparison — the **concrete costs** — so the
C5 table can put Chia and the proposed scheme side by side. For each scheme it records five costs:

> **"Proof size (bytes), prover time, verifier time, plot time, plot size — for the proposed v3
> scheme (MEASURED) and for Chia (CITED)."**

The proposed scheme's costs are measured in this repo; Chia's are taken from published sources. The
fair comparison is at **matched plot scale**: the thesis plot N = 3,355,443,200 ≈ **100 GiB** of labels
≈ Chia **k=32 (101.4 GiB)**.

### Headline finding

**At matched ~100 GiB, v3 trades larger proofs for seek-free, in-RAM proving.** (δ=2 vs Chia k=32)

| cost | proposed v3 (δ=2, thesis N) | Chia (k=32) | reading |
|---|---|---|---|
| proof size | **3 168 B (3.09 KiB)** | **256 B** | v3 ~12× larger — the cost of opening 1+δ DRG parents, each with a Merkle path |
| plot time | **164.8 s** (native floor) | **~300 s** high-end (→ ~6 h commodity) | comparable; v3 is one SHA-256 per label |
| plot size | **100 GiB** labels (≈200 GiB w/ tree) | **101.4 GiB** | matched by construction |
| prover | **~7 µs** (in-RAM Merkle open) | **~640 ms** (slow-HDD quality lookup, 10 ms/seek) | v3 has no disk-seek proving cost |
| verifier | **~17 µs** (check 1+δ paths + label eq.) | near-instant, **no published ms** | both cheap; v3's is measured |

*(v3 rows: `source=extrapolated_v3` at thesis N, prove/verify carried from the measured 2^16 anchor.
Chia row: `source=chia_cited`.)* Proof size grows linearly in the DRG in-degree δ: **3.09 / 5.16 /
9.28 KiB** for δ=2/4/8 at thesis N — the "what is lost" that C5 weighs against the security δ buys.

## Why a microbenchmark, not the Docker testbed

Proof size and prover/verifier/plot cost are properties of the **PoSpace plot**, not the DNS ring —
there is nothing for Docker, netem, or a Chord ring to add. Like A7/B2/B5/C1–C3, C4 is a no-Docker
microbenchmark that times the node's exact admission functions directly.

## Metric — how each number is produced

**Proposed v3 — `source=measured_v3` (fresh anchor at 2^16).** The driver times the node-imported
`plot_v3` / `commit_v3` / `prove_v3` / `verify_v3` over the 8 deterministic ring keys `_pk_for(0..7)`
× 3 repeats × 30 random challenges, using the **identical recipe** as
[`experiments/a7_admission.py`](../experiments/a7_admission.py) (`time.perf_counter()`; proof bytes =
`sum(len(lbl) + 32·len(path))` over the opened nodes). CSV columns: `proof_size_bytes` (median),
`prover_ms`, `verifier_ms`, `plot_time` (s), `plot_size` (GiB). These reproduce the committed A7 sweep
(**1632 / 2720 / 4896 B** proof at 2^16 for δ=2/4/8), cross-cited to
[`A7_admission.csv`](A7_admission.csv).

**Proposed v3 — `source=extrapolated_v3` (fair same-scale, thesis N ≈ 100 GiB).**
- `proof_size_bytes` = **`(1+δ)·(1+⌈log₂N⌉)·32`** bytes — exact and *measured == analytic* (the A7/bench
  self-check; [`phase1/FIX_A.md`](../phase1/FIX_A.md) §4). At N = 3,355,443,200 (⌈log₂N⌉ = 32):
  **3168 / 5280 / 9504 B** for δ=2/4/8.
- `plot_time` = the **native-rate floor** read from
  [`phase1/results/results_plot_extrap_v3.csv`](../phase1/results/results_plot_extrap_v3.csv)
  (`plot_time_100GiB_native_s`): **164.8 / 247.2 / 411.3 s** for δ=2/4/8 (one SHA-256 per label at
  20.363 MH/s; [`chainrate.csv`](../phase1/results/chainrate.csv)).
- `plot_size` = **100 GiB** of 32-byte labels (≈200 GiB with the Merkle tree).
- `prover_ms` / `verifier_ms` = **carried from the 2^16 anchor** — these are size-independent to first
  order: a proof opens 1+δ nodes regardless of N, and the only N-dependence is the Merkle-path length
  (⌈log₂N⌉ hashes), a handful of extra hashes ≪ the 50–300 ms network RTT. **Flagged** as a toy-scale
  timing (see caveats).

**Chia — `source=chia_cited` (k=32, published).** Every field cited, none measured here; the source URL
is in the `note` column:
- proof size **256 B** = 64 x-values × k=32 bits — Chia docs, *Proof of Space 1.0*
  (<https://docs.chia.net/chia-blockchain/consensus/proof-of-space-1.0/>).
- plot size **101.4 GiB** = `780·k·2^(k−10)` bytes — same source.
- plot time **~5 min** on a high-end machine (400 GiB RAM) up to **~6 h** commodity, Chia 1.2.7 — Chia
  docs, *Plotting Basics* (<https://docs.chia.net/reference-client/plotting/plotting-basics/>). The CSV
  records 300 s (5 min); modern madMAx/bladebit plotters are faster (flagged).
- prover **~640 ms** quality/proof lookup on a slow HDD (10 ms/seek, **plot-size-independent**) — Chia
  consensus paper (<https://www.chia.net/wp-content/uploads/2022/09/Chia-New-Consensus-0.9.pdf>).
- verifier **near-instant** ("a few hashes + comparisons", no disk) — *Proof of Space 1.0*; **no
  published ms benchmark** (CSV leaves `verifier_ms` blank, figure shows `n/p`).
- Theory lineage: *Beyond Hellman's Time-Memory Trade-offs* [AACKPR17] (cited in
  [`phase1/FINDINGS.md`](../phase1/FINDINGS.md):322).

## The new driver — no frozen artifact touched

- **New:** [`experiments/c4_proof_metrics.py`](../experiments/c4_proof_metrics.py),
  [`experiments/run_c4.sh`](../experiments/run_c4.sh), and the deliverables
  `results/C4_proof_metrics.csv` / `fig_C4_proof_metrics.png` / this file.
- **Imported, never copied:** `plot_v3`/`commit_v3`/`prove_v3`/`verify_v3` (via
  `node/pospace_admission.py`), `drg.parents_all`, `node/ids.py`, `node/run_node._pk_for`.
- **Read only:** [`A7_admission.csv`](A7_admission.csv),
  [`phase1/results/results_plot_extrap_v3.csv`](../phase1/results/results_plot_extrap_v3.csv),
  [`chainrate.csv`](../phase1/results/chainrate.csv), `REAL_PLOT_N`.
- `rpos/rpos.py`, all of `phase1/*` and `node/*` stay **byte-identical** (CLAUDE.md §2).

## Honest caveats (flag, don't hide — CLAUDE.md §2)

1. **v3 prove/verify are measured at toy scale (2^16) and carried to thesis N.** They are
   size-independent to first order (1+δ opened nodes; +⌈log₂N⌉ Merkle hashes per path — ~16 extra
   hashes at thesis N vs 2^16, i.e. tens of µs, ≪ network RTT). The *proof-size* extrapolation is exact
   (closed formula), but the *timing* extrapolation assumes the per-hash cost is the bottleneck; it is
   reported as a flagged carry, not a re-measurement at 100 GiB.
2. **v3 plot time is a native-rate model, not a wall-clock C plot at 100 GiB.** The 164.8–411.3 s
   figures are the single-core native floor (one SHA-256 per label at 20.363 MH/s); the committed
   pure-Python plotter is ~33–55× slower, and real plotting adds I/O (both tabulated in
   `results_plot_extrap_v3.csv`). We compare the native floor to Chia's documented plotter time — a
   like-for-like "optimised implementation" comparison, stated as such.
3. **Scale/hardware mismatch (the issue's explicit ask).** Our directly-*measured* v3 anchors are at
   2^16 (a 2 MiB toy plot); the thesis-scale v3 row is *extrapolated*. Chia's numbers are at real k=32
   (101.4 GiB) on Chia's documented hardware (and partly on a slow-HDD seek model). The comparison is
   fair on **plot size** (100 GiB ≈ 101.4 GiB) and on **plot time** (native-floor vs documented
   plotter), but proof/prove/verify mix measured-ours against cited-theirs; `source`/`scale`/`note`
   columns mark every row.
4. **Chia verifier time has no published ms figure** → cited qualitatively (near-instant); `verifier_ms`
   is blank. A targeted search (chiapos `validate_proof`, the Chia consensus/PoS docs) found only the
   ~640 ms *full-lookup* figure (prover side, HDD-seek bound), which is not a verification benchmark.
5. **DRG in-degree δ (and the δ-vs-proof-size trade) still awaits cryptographer sign-off** (Phase 1
   "Open"). C4 reports the cost at δ∈{2,4,8}; which δ the thesis fixes is a security choice C5 frames.

## How to reproduce

```bash
bash experiments/run_c4.sh                                 # self-test, then full run -> CSV + PNG
C4_ANCHOR_LOG2=14 C4_REPEATS=2 bash experiments/run_c4.sh  # faster anchor (smoke)
python3 experiments/c4_proof_metrics.py --self-test        # deterministic checks only
```

Deterministic (seed 20260919); the measured anchor varies by a few µs/ms run-to-run (timing), the
proof sizes / thesis-scale rows / Chia rows are exact.

## Output schema (`C4_proof_metrics.csv`)

| column | meaning |
|---|---|
| `scheme` | `proposed_v3` or `chia` |
| `parameter` | `delta=2\|4\|8` (v3 DRG in-degree) or `k=32` (Chia plot parameter) |
| `proof_size_bytes` | proof size in bytes (v3 measured/formula; Chia cited) |
| `prover_ms` | prover (proof-generation / lookup) time, ms |
| `verifier_ms` | verifier time, ms (blank = no published figure, Chia) |
| `plot_time` | plot/commit time in **seconds** |
| `plot_size` | plot size in **GiB** |
| `source` | provenance: `measured_v3`, `extrapolated_v3`, or `chia_cited` |
| `scale` | the scale the row is stated at (`2^16 (toy)`, `N=… (~100 GiB)`, `k=32 (101.4 GiB)`) |
| `note` | per-row provenance: repo measurement cited (v3) / source URLs (Chia) / flags |
