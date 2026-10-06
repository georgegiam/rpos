# B2 — Targeted chunk-majority capture / ID grinding: methodology notes (issue #43, Phase 7, examiner point (ii))

Reproducible trail for the B2 attack experiment. Numbers live in
[`B2_targeted.csv`](B2_targeted.csv) and [`fig_B2_targeted.png`](fig_B2_targeted.png); this file
records *how* they are produced and the honest caveats (CLAUDE.md §2 "measure, don't assert" /
"flag, don't hide").

## What B2 measures

Can an adversary capture a **majority** (`≥ ⌈(s+1)/2⌉ = 2` of `s=3`) of a target domain's replicas,
and what does it **cost**, for *random* vs *targeted* placement? And can node IDs be **ground**
(`pk → ID`) to land on a chosen chunk's replica slots? B0 (#41) frames B2 as a **cost axis, not an
f-sweep**; B1 (#42) explicitly deferred *"the cost of achieving such placement by grinding ids"* to
here (B1_NOTES caveat 4).

The replica set of a domain is **`s` consecutive ring nodes** starting at
`successor_of(chunk_id(domain))` ([`node/storage.py::replica_set`](../node/storage.py)); to own a
majority an attacker must occupy `⌈(s+1)/2⌉` of those consecutive slots.

### Headline finding — ID grinding is trivially cheap; PoSpace limits identity *count*, not *placement*

`node_id = SHA-256(pk) mod 2¹⁶⁰` is **unsalted** and the attacker **picks its own `pk`**
([`node/ids.py`](../node/ids.py), [`node/pospace_admission.py`](../node/pospace_admission.py)). The
ring is astronomically sparse (`N ≪ 2¹⁶⁰`), so landing an id in one inter-node gap (width `≈2¹⁶⁰/N`)
takes **`≈N` hashes in expectation** — a geometric search the attacker runs by hashing candidate
`pk`s and plotting only the winner. Admission binds `pk`↔position (the challenger rejects any node
where `node_id_from_pk(pk) ≠ peer_id`, and the plot is keyed by `pk`), so the **only real cost is one
PoSpace plot per *admitted* identity**. PoSpace therefore rate-limits the **number** of identities,
**not where they land**.

Consequence (the examiner-facing result):

* **Targeted capture of any chosen chunk costs a *constant* `⌈(s+1)/2⌉ = 2` plotted identities**
  (just **1** under B1's measured `≥1-of-s` vote weakness), independent of `N` and of the target's
  popularity — grind 2 ids into the one gap before the chunk's current successor, plot them, join.
* **Random placement needs `≈O(N)` plotted identities** to capture a *chosen* chunk, and even then
  only probabilistically — it is effective for *"capture some chunk"*, useless for *"capture this
  chunk"*.

## Metric

* **Grindability** — `hashes` for `node_id_from_pk(pk) = SHA-256(pk)` to land in a chosen ring
  window of width `2¹⁶⁰/N` (one mean gap), swept over `N`, in hashes and seconds (native-C floor at
  the measured **20.36 MH/s** chain rate from [`phase1/results/chainrate.csv`](../phase1/results/chainrate.csv),
  plus measured Python).
* **Capture cost** — number of **plotted identities** needed to own `⌈(s+1)/2⌉` of a *chosen*
  chunk's `s` replicas: constant for targeted; the smallest `m` random identities with
  `P(capture) ≥ p` for `p ∈ {0.5, 0.9, 0.99}` via the exact (slot-centric) **hypergeometric**
  `P(exactly k of s slots malicious) = C(m,k)·C(N−m,s−k)/C(N,s)` (`math.comb`, no SciPy).
* **Admission demo** — a real in-process PoSpace ring where a grinded `pk` is **admitted** (genuine
  v3 plot + challenge) and **becomes the target chunk's primary** (and serves the forged value).

## Results (N=32 real ring, s=3, seed 20260919, 20.36 MH/s)

### Block 1 — grinding cost is `O(N)` and negligible at every scale

| ring size N | gap width | E[hashes]=N | measured hashes | native-C time |
|---:|---:|---:|---:|---:|
| 32 | 2¹⁵⁵ | 32 | 54 | 0.003 ms |
| 1 000 | 2¹⁵⁰ | 1 000 | 904 | 0.044 ms |
| 1 000 000 | 2¹⁴⁰ | 1 000 000 | 2 130 019 | 105 ms |
| 1 000 000 000 | 2¹³⁰ | 1 000 000 000 | *(extrapolated)* | **~49 s** |

Measured hashes track the geometric expectation `E = 2¹⁶⁰/gap = N`; even at a **billion-node**
internet-scale ring, grinding a chosen position is ~49 s of native SHA-256 (≈9 min single-core
Python) — **dwarfed by the per-identity plot** (A7: ~1.6 ms at 2¹⁰, minutes at the 200 GiB thesis
plot). Concrete instance: the popular, node-0-free target **`google.com`** is captured by grinding
its `⌈(s+1)/2⌉ = 2` ids in **53 hashes total** (0.003 ms native).

### Block 2 — capture cost: targeted `O(1)` vs random `O(N)`

| N | targeted (majority) | targeted (≥1-of-s, B1) | random @50% | random @90% | random @99% |
|---:|---:|---:|---:|---:|---:|
| 32 | **2** | **1** | 16 | 26 | 30 |
| 1 000 | **2** | **1** | 500 | 804 | 941 |
| 1 000 000 | **2** | **1** | 500 000 | 804 200 | 941 097 |
| 1 000 000 000 | **2** | **1** | 500 000 000 | 804 199 895 | 941 096 864 |

Targeted stays at **2 plots** (1 under the B1 weakness) for *every* N; random rises linearly in N
and, at the thresholds for near-certain capture of a *chosen* target, approaches corrupting the
whole ring. Grinding is what makes the targeted column achievable — PoSpace does not raise it.

### Block 3 — in-process admission demo (`source=admission_inproc`): the chain is real

On a real 8-node in-process PoSpace ring (the A7 `create()`/`join()` pattern), a grinded `pk`
(id in the open gap before `google.com`'s honest primary) was **admitted** — it built a genuine v3
DRG plot and passed its successor's challenge — and after convergence **became the chunk's primary**
(`find_successor(chunk) == malicious id`). Storing the forged A-record on it and reading back through
an honest node returned the forgery (`forged_served = True`), reproducing B1's `≥1-of-s` capture
end-to-end from a *ground* identity.

### Control

Honest **f=0** placement captures **0** of the served chunks (`structural_capture_fraction([]) =
0.0`): the capture is **adversary-caused**, and it is a **protocol/design property** (unsalted
`id = H(pk)` + a sparse ring), **not `chord.py` reference-implementation fragility** (the epic's
cross-cutting requirement — B2 touches no live ring maintenance).

## The new driver (no frozen edit — CLAUDE.md §2)

* [`experiments/b2_grinding.py`](../experiments/b2_grinding.py) — the analyzer + `--self-test`.
  **Imports/reads only**: reuses [`experiments/b1_placement.py`](../experiments/b1_placement.py)
  (`build_ring`, `targeted_indices`, `capture_threshold`, `structural_capture_fraction`,
  `load_served_domains`) and [`node/ids.py`](../node/ids.py); the in-process demo lazily imports
  `PoSpaceNode`/`Network`/`_pk_for` (skipped with a clear note if dnspython is absent, so the cost
  analysis runs anywhere). Writes `results/B2_targeted.csv` + `results/fig_B2_targeted.png`.
* [`experiments/run_b2.sh`](../experiments/run_b2.sh) — thin A7-style wrapper (self-test → analysis,
  **no Docker**).

`rpos/rpos.py`, `node/chord.py`, `node/storage.py`, `node/ledger.py`, `node/pospace_admission.py`,
`node/net.py`, `phase1/pospace_drg.py` and `experiments/b1_placement.py` are byte-identical.

## Workload (frozen — PARAMETERS.md)

N=32 real emulation ring; s=3; grind-scale sweep {32, 10³, 10⁶, 10⁹} (empirical ≤10⁶, geometric
expectation at 10⁹); capture probabilities {0.5, 0.9, 0.99}; in-process demo ring N=8 at plot 2¹⁰;
SHA-256 rate 20.36 MH/s (chainrate.csv); seed 20260919.

## Honest caveats (flag, don't hide — CLAUDE.md §2)

1. **The 10⁹ grind point is extrapolated, not ground.** `E[hashes] = 2¹⁶⁰/gap = N` is the *exact*
   geometric mean, validated against the measured points at N ≤ 10⁶; grinding 10⁹ hashes in Python
   (~9 min) is skipped as it adds nothing. Flagged `source=extrapolated` in the CSV.
2. **High geometric variance at large N, few reps.** The grind length is geometric
   (sd ≈ mean), and N=10⁶ uses only 2 reps, so the measured 2.13 M vs E=1 M is within one sampling
   fluctuation; the **expectation line is the anchor**, the measured points confirm the slope.
3. **The `≥1-of-s` effective bound (targeted=1 plot) comes from B1, not re-measured here.** B2
   reports both the nominal majority (2) and the B1-measured effective (1) targeted costs.
4. **The demo uses a 2¹⁰ test plot.** It proves the *grind → admission → capture* chain, not the
   plot cost — that cost (ms test-scale → minutes at 200 GiB) is quantified separately by A7 and is
   the true per-identity price of every row in the capture-cost table.
5. **Random placement here targets a *chosen* chunk** (the adversary-relevant question). The
   *fraction of all chunks* a random adversary captures is the B1 bound `1−(1−f)^s` and is not the
   subject of this cost axis.

## How to reproduce

```bash
python3 experiments/b2_grinding.py --self-test     # deterministic checks (incl. the in-process demo)
bash experiments/run_b2.sh                          # self-test, then full analysis -> CSV + PNG
python3 experiments/b2_grinding.py --no-demo        # cost analysis only (no dnspython needed)
```

Run under the 3.11 experiment env (dnspython + matplotlib). Seed 20260919 → identical grind
counts, capture costs, and the same grinded identities.

## Output schema (`B2_targeted.csv`)

| column | meaning |
|---|---|
| `metric` | `grind_scale` / `grind_target` / `capture_cost` / `admission_demo` / `control` |
| `source` | `measured` / `extrapolated` / `real_ring` / `analytic` / `admission_inproc` |
| `strategy` | `targeted_majority` / `targeted_effective` / `random_p{50,90,99}` / `targeted` / `honest` |
| `N`, `s`, `threshold` | ring size, replication factor, replicas needed to capture (`⌈(s+1)/2⌉` or 1) |
| `window_bits` | log₂ of the grind window / target gap width |
| `identities_needed` | plotted identities to capture a chosen chunk (the capture-cost headline) |
| `hashes_expected`, `hashes_measured` | geometric expectation vs measured grind length |
| `seconds_native`, `seconds_python` | grind wall-clock at 20.36 MH/s (C floor) and measured Python |
| `capture_prob` | random: target success probability; targeted/demo: 1.0; control: realized capture fraction |
| `admitted` | demo only: `yes` / `no` / `skipped` |
| `note` | per-row detail (target domain, bound, caveat) |
