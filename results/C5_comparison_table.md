# C5 — Chia PoSpace vs the proposed v3 DRG scheme: full comparison + "what is lost by gaining efficiency"

*Issue #54, Phase 8 **capstone**, examiner **point (i)**.* This is the row-by-row security comparison
the examiners asked for, with the explicit **"what is lost"** column and the synthesis discussion
(§"What is lost — the discussion", below). It answers:

> *"What security does the proposed scheme trade away for its lower cost, and is that trade-off
> justified for DNS resolution?"*

**This is pure synthesis — no new measurement.** Every **proposed-side** number traces to an
already-committed repo measurement (C1–C4, B2, B5, Phase 1); every **Chia-side** number traces to a
published source (URLs in the "Sources" key). The companion CSV
[`C5_comparison_table.csv`](C5_comparison_table.csv) carries the same 14 rows machine-readably, and
[`experiments/c5_comparison.py --self-test`](../experiments/c5_comparison.py) re-reads the source CSVs
and **asserts every numeric cell still equals its source** (31 pinned cells, all passing) — the
CLAUDE.md §2 "measure, don't assert" guarantee that this capstone cannot drift from the experiments it
summarises.

**Fair comparison basis.** The schemes are compared at **matched plot scale**: the thesis plot
**N = 3,355,443,200 labels ≈ 100 GiB** ≈ Chia **k = 32 (101.4 GiB)**. Native SHA-256 rate
**20.36 MH/s** (single-core M4, `phase1/results/chainrate.csv`). The DRG in-degree δ (the node default
is **δ = 2**) is swept over {2, 4, 8}.

**Fairness (the issue's explicit requirement).** Every row appears in **both directions**. Chia wins
rows 3, 5, 8, 9, 12, 14 (stronger/battle-tested space bound, 12× smaller proofs, non-interactive with
no timeout δ, VDF composability, maturity). The proposed scheme wins rows 2, 6, 7, 12 (simpler
construction, ~5-orders-faster prover, comparable plot time, no blockchain dependency). Rows are **not**
cherry-picked.

---

## The comparison table (14 rows × 4 columns)

Columns: **Chia** | **Proposed v3** | **What is gained** | **What is lost**. Each numeric cell cites
its source (compact tag; full URLs/paths in the "Sources" key).

### 1. Underlying hard problem
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| Inverting a sequence of functions; time-memory-trade-off (TMTO) hardness, "Beyond Hellman" [AACKPR17] | Pebbling/labelling of an **(e,d)-depth-robust DAG**; sequential-recompute lower bound [DFKP15, ABH17] | One well-studied primitive (a single DRG); the verifier reconstructs the graph bit-for-bit from `pk` | **Narrower foundation** — rests on one *single-layer* DRG's depth-robustness vs Chia's layered function-inversion hardness |

### 2. Graph / plot construction
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| **7 tables** (Beyond-Hellman nested 6×), 2^k entries each; plot phases forward-propagation → backpropagation → **compression** → checkpoints [Chia PoS Construction v1.1] | **DRSample single-layer DRG** (bucket-method back-edges); `l_i = H(pk‖i‖parent labels)`; Merkle-committed [FIX_A §1] | **Far simpler plotting** (one SHA-256 pass/label); data-independent, verifier-reproducible from `pk` | Single layer, **no table compression**; far less engineering maturity; no compressed on-disk format |

### 3. Space lower bound (asymptotic + measured)
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| TMTO lower bound from the layered-table construction [AACKPR17] | Asymptotic **Ω(N/log N)** depth-robustness [ABH17]; **measured back-cone φ ≈ 0.49·N** at thesis N [C1] | A concrete, **measured** space floor on the actual plot (not only asymptotic) | Bound is **asymptotic + single-layer**; measured φ **extrapolated ~800× beyond** the measured range, not re-proven at thesis N |

### 4. Time–space trade-off curve
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| Partial storage resisted by table design; **no published** recompute-vs-storage curve | keep 25% labels → **12.99 s** recompute; keep ≤10% → **60–81 s**; honest ~tens of ms; φ saturates ≈0.49 [C1] | A **measured** trade-off curve that makes a usable response timeout δ possible | Holds under the **sequential** model; an unlimited-core parallel attacker floor ≈ **5.15 s** [C1] |

### 5. Proof size
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| **256 B** (k=32) [Chia PoS 1.0] | **3168 B** (δ=2) / 5280 (δ=4) / 9504 (δ=8) at thesis N [C4] | Self-contained proof: a verifier-reconstructible DRG parent set + Merkle paths, no table lookups | **~12× larger** than Chia (256 B → 3168 B), and **grows linearly in δ** |

### 6. Prover / verifier time
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| prover **~640 ms** (slow-HDD quality lookup, 10 ms/seek); verifier near-instant, **no published ms** [Chia consensus 0.9] | prover **~7 µs**; verifier **~17 µs** (in-RAM Merkle open) [C4] | **Seek-free, in-RAM proving** — prover ~5 orders of magnitude faster than Chia's disk lookup | Assumes the plot is RAM/fast-readable; Chia is *designed* to tolerate a slow HDD |

### 7. Plot initialisation time + size
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| **~300 s** high-end (400 GiB RAM) → **~6 h** commodity; **101.4 GiB** (k=32) [Chia plotting] | **164.8 s** native floor (δ=2; up to 411 s at δ=8); **100 GiB** labels (≈200 GiB with Merkle tree) [C4] | Comparable/faster **native** plot; one SHA-256/label, no multi-phase compression | Native-rate floor (pure-Python ~33–55× slower); **≈200 GiB on disk** with the tree vs Chia's compressed 101.4 GiB |

### 8. Challenge–response protocol
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| **Non-interactive**: challenge broadcast from the blockchain at each **signage point**; the farmer self-checks its plot (no per-prover request) [Chia consensus challenges] | **Interactive**: a peer challenges a peer over the DHT; the prover answers within a response timeout **δ** | No blockchain/timelord required; fits a **live DHT** where nodes already exchange RPCs every maintenance round | Relies on an **interactive liveness assumption** and a wall-clock timeout **δ** that Chia avoids entirely |

### 9. δ (timeout) sensitivity
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| **N/A** — Chia has no response-timeout δ | false-reject ≈0 for all δ≥1 s (honest p99 cross-region **146.5 ms**); **false-accept = 0 for δ≤2 s**; δ=5 s marginal vs the 5.15 s parallel floor [C2] | **δ≤2 s cleanly separates** honest from cheater under realistic network jitter | Correctness hinges on a **tuned δ** + jitter assumptions; a loose δ (=10 s at δ_g=8 / keep-75%) **admits a cheater** [C2] |

### 10. Detection probability
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| **N/A** at the PoSpace layer — soundness/identity enforced by consensus, not per-node liveness challenges | ρ≤20% labels → caught by the **1st** challenge (p_fail 0.89–0.97); evicted in **3** consecutive fails (`MAX_FAILS`); knee at ρ≈25% [C3] | Cheap **periodic challenges** catch storage-cheaters quickly and evict them | A cheater keeping **≥33%** labels escapes the δ=2 s timeout (but then stored ≈75% of the tree); detection is **recompute-time-bound**, not coverage-bound |

### 11. Grinding / Sybil resistance
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| Plot-grinding costly by construction; **"ungrindable trunk"** (PoSpace+VDF only); identity enforced at consensus level [Chia green paper] | `id = SHA256(pk)` **unsalted & attacker-chosen** → grindable in ~N hashes (targeted capture = **const 2 plots** [B2]); per-identity cost **×3.25×10⁹** vs no admission [B5]; **but a minimum-plot-size check is MISSING** (B5 gate **FAIL**) | PoSpace **raises per-identity cost ~3.25×10⁹×** (33 B keypair → 100 GiB plot) and rate-limits the *number* of identities | **Rate-limits count, not placement** — the unsalted id is grindable; the Sybil-cost floor is **conditional** on an unimplemented minimum-plot-size check |

### 12. Composability
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| Chained with a **VDF** ("Proof of Time", class-group repeated squaring by timelords) → blockchain-grade consensus [Chia proof-of-time] | **Standalone** PoSpace admission over the DHT; no VDF, no chain | **No timelord/VDF/blockchain dependency** — self-contained node admission | **No proof-of-elapsed-time or global ordering**; cannot give the consensus-grade guarantees Chia's VDF provides |

### 13. Amortisation resistance
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| Beyond-Hellman table format resists TMTO [AACKPR17]; grinding-resistant trunk | DRG depth-robustness (no sub-linear retention [C1]) + **no-plot-amortisation**: k identities need k distinct plots, distinct roots (B5 gate **PASS**); `pk↔id` binding blocks plot reuse (B5 gate **PASS**) | **Provably one plot per identity**; a Sybil advertising another identity's commitment is rejected by `challenge_peer` | Amortisation **within** one plot (across challenges) not separately hardened; rests on the single DRG's depth-robustness |

### 14. Known attacks + mitigations
| Chia | Proposed v3 | Gained | Lost |
|---|---|---|---|
| **Mature, audited, deployed since 2021**; plot-grinding/replotting trade-offs handled at the consensus layer | v1/v2 scheme breaks **found & fixed** by v3 DRG (Phase 1); residual: B1 ≥1-of-s forge, B6 unvalidated ledger proposer, B2 id grinding, B5 missing min-plot — each with a **recommended (unimplemented)** mitigation | Breaks were **found and fixed before resubmission**; a clear, measured mitigation list | **Unaudited, not battle-tested**; several recommended mitigations remain unimplemented; DRG parameters await cryptographer sign-off |

---

## Sources

**Proposed-side (repo measurements):**
- **C1** — [`C1_retention_attack.csv`](C1_retention_attack.csv) / [`C1_NOTES.md`](C1_NOTES.md): time–space trade-off, back-cone φ, parallel floor.
- **C2** — [`C2_delta_jitter.csv`](C2_delta_jitter.csv) / [`C2_NOTES.md`](C2_NOTES.md): δ sensitivity, false-reject/false-accept under jitter.
- **C3** — [`C3_detection.csv`](C3_detection.csv) / [`C3_NOTES.md`](C3_NOTES.md): detection probability, eviction.
- **C4** — [`C4_proof_metrics.csv`](C4_proof_metrics.csv) / [`C4_NOTES.md`](C4_NOTES.md): proof size, prover/verifier/plot cost.
- **B2** — [`B2_targeted.csv`](B2_targeted.csv) / [`B2_NOTES.md`](B2_NOTES.md): id grinding, targeted capture cost.
- **B5** — [`B5_sybil.csv`](B5_sybil.csv) / [`B5_NOTES.md`](B5_NOTES.md): Sybil budget, per-identity cost, admission gates.
- **Phase 1** — [`phase1/FINDINGS.md`](../phase1/FINDINGS.md), [`phase1/FIX_A.md`](../phase1/FIX_A.md): construction, lower bound, caveats.

**Chia-side (published):**
- Chia *Proof of Space Construction v1.1* — <https://www.chia.net/wp-content/uploads/2022/09/Chia_Proof_of_Space_Construction_v1.1.pdf> (7 tables, plot phases).
- Chia *Proof of Space 1.0* — <https://docs.chia.net/chia-blockchain/consensus/proof-of-space-1.0/> (256 B proof, 101.4 GiB plot, near-instant verify).
- Chia *Plotting Basics* — <https://docs.chia.net/reference-client/plotting/plotting-basics/> (plot time ~5 min → ~6 h).
- Chia *New Consensus 0.9* — <https://www.chia.net/wp-content/uploads/2022/09/Chia-New-Consensus-0.9.pdf> (~640 ms HDD quality lookup).
- Chia *Proof of Time* — <https://docs.chia.net/proof-of-time> (VDF, class-group repeated squaring).
- Chia *Consensus Challenges* — <https://docs.chia.net/consensus-challenges/> (signage points, broadcast challenges).
- Chia *Green Paper* — <https://docs.chia.net/files/ChiaGreenPaper_20241008.pdf> (ungrindable trunk/foliage; maturity).
- **[AACKPR17]** Abusalah–Alwen–Cohen–Khurana–Pietrzak–Reyzin, *Beyond Hellman's Time-Memory Trade-Offs*, ASIACRYPT 2017.
- **[ABH17]** Alwen–Blocki–Harsha, *Practical Graphs for Optimal Side-Channel Resistant Proofs of Space*, CCS 2017.
- **[DFKP15]** Dziembowski–Faust–Kolmogorov–Pietrzak, *Proofs of Space*, CRYPTO 2015.

*Comparison caveats (stated per row, re-stated here):* our directly-*measured* v3 anchors are at toy
2^16 and carried/extrapolated to thesis N (proof size via the exact closed formula, prover/verifier
size-independent to first order, plot time via the native-rate floor); Chia's numbers are at real k=32
on Chia's documented hardware, and its prover figure is a slow-HDD **seek** model. The comparison is
fair on **plot size** (100 GiB ≈ 101.4 GiB) and **plot time** (native floor vs documented plotter);
proof/prove/verify mix *measured-ours* against *cited-theirs*, and every row flags its scale/hardware
mismatch. Chia's verifier has **no published ms** figure (cited qualitatively). DRG in-degree δ and the
target depth-robustness **await cryptographer sign-off** (Phase 1 "Open").

---

## What is lost — the discussion

The examiners' point (i) is not "is the proposed scheme good?" but "**what security does it trade away
for its lower cost, and is that trade justified?**" The honest answer has six distinct losses, each
tied to a row above, and a single reason they are acceptable *for DNS resolution specifically*.

**1 — A weaker, less battle-tested space lower bound (rows 1, 3, 4).** This is the deepest loss. Chia's
plot is a nested stack of seven function tables whose TMTO-hardness has a decade of cryptanalysis behind
it [AACKPR17] and five years of adversarial deployment. The proposed scheme leans on a **single-layer**
DRSample DRG, and the guarantee we actually invoke is **asymptotic** (Ω(N/log N) depth-robustness
[ABH17]). Our concrete separation rests on the *measured* back-cone fraction φ ≈ 0.49·N (C1) —
reassuringly flat across the measured sizes, but **extrapolated ~800× beyond** the largest plot we could
build (2^22 labels → thesis N), relying on DRSample's asymptotic promise rather than a from-scratch
pebbling proof at thesis scale. We do not hide this: the single-layer margin is the first thing a
cryptographer should check, and FIX_A §5 already names the **stacked-DRG (SDR)** fallback if the margin
is judged thin. What is *gained* is that, unlike Chia, we can put a measured number on the actual plot —
but it is a measured number resting on an unproven extrapolation, and that is the trade.

**2 — ~12× larger proofs, growing in δ (row 5).** A v3 proof is **3168 B** at δ=2 versus Chia's **256 B**,
because it opens 1+δ DRG parents each with a Merkle path, and it grows *linearly* in the in-degree δ
(9504 B at δ=8). Chia wins this axis outright.

**3 — Reliance on a response timeout δ that Chia avoids (rows 8, 9).** Chia's challenge is
**non-interactive**: it falls out of the blockchain at each signage point and the farmer self-checks its
plot, so there is no clock to tune and no liveness assumption. The proposed scheme is **interactive** — a
peer challenges a peer and the prover must answer within δ — which imports two things Chia does not have:
an interactive liveness assumption, and a wall-clock timeout whose *value matters*. C2 shows δ≤2 s cleanly
separates honest from cheater under real jitter (honest cross-region p99 is only 146.5 ms, false-accept
is 0), but it also shows the knife-edge: at a loose δ=10 s with a high in-degree and a 75%-keeper the
cheater gets *in* (false-accept → 1). Correctness now depends on a parameter choice and a network model,
which Chia's design sidesteps entirely.

**4 — No VDF / no consensus-grade composability (row 12).** Chia composes PoSpace with a VDF ("Proof of
Time") to build a full, grinding-resistant blockchain with global ordering. The proposed scheme is
**standalone**: it admits nodes to a DHT and nothing more. It cannot provide proof-of-elapsed-time or a
total order, and it inherits none of the trunk/foliage grinding defences that Chia's VDF chain buys.

**5 — Two unimplemented mitigations that *conditionally* weaken the Sybil story (rows 11, 14).** This is
the most actionable loss. PoSpace admission genuinely raises the per-identity cost by **~3.25×10⁹×** (a
33 B keypair becomes a 100 GiB plot, B5) — but two gaps in the *reference code* blunt it. First, the node
id is `SHA256(pk)` **unsalted and attacker-chosen**, so an adversary grinds a chosen position in ~N
hashes and captures any target chunk for a constant **2 plots** (B2); PoSpace rate-limits the *number* of
identities, not *where* they land. Second, admission enforces **no minimum plot size** (B5 gate FAIL): an
under-sized Sybil is admitted, so the `⌊budget/100 GiB⌋` identity floor is *conditional* on a check the
code does not yet make. Neither is a protocol-theory flaw — both are fixable (salt/bind the id to the
committed plot root; add a `MIN_PLOT_N` check) — but as shipped they are real losses the thesis must flag,
not bury.

**6 — Maturity (row 14).** Chia is audited and deployed; the proposed scheme is a research prototype whose
v1 and v2 designs were found *broken* during this very work (Phase 1) and fixed only at v3, with several
recommended mitigations (B1 quorum vote, B6 proposal validation, the two B2/B5 fixes) still unimplemented
and the DRG parameters still awaiting cryptographer sign-off.

**Against these six losses, the gains are concrete:** a **~5-orders-of-magnitude faster prover** (~7 µs
in-RAM vs ~640 ms disk-seek, row 6), a **comparable native plot time** (164.8 s vs ~300 s, row 7), a far
**simpler, data-independent, verifier-reproducible construction** (rows 1–2), and **no blockchain, VDF, or
timelord dependency** (row 12) — a scheme a DNS resolver can actually run in-process on every node.

**Why the trade is justified for DNS resolution.** The resolver's security requirement is narrow and
specific: **rate-limit Sybil identities** so no cheap flood of fake nodes can capture the DHT, and do it
**cheaply enough to run on every node continuously**. It does *not* need Chia's blockchain-grade
non-interactive consensus, its global plot-grinding resistance, or a VDF chain — those defend a
multi-billion-dollar permissionless ledger against a global adversary, which is not the threat model of a
cooperative DNS overlay. The two properties the proposed scheme trades *for* — interactivity and a timeout
δ — are **natural in this setting**: the nodes already exchange RPCs every maintenance round, so a
challenge-response with a δ≤2 s deadline costs nothing extra, and C2 shows it separates honest from cheater
with margin under realistic jitter. The scheme therefore trades **theoretical margin and battle-testing**
(which DNS does not strictly need) for **operational simplicity and proving speed** (which it does) — the
right trade for this use case, **provided** the two flagged implementation gaps (unsalted id, missing
minimum-plot-size check) are closed and the DRG parameters receive the cryptographer sign-off Phase 1
already made a precondition of any final claim. The one trade we cannot fully discharge within this work
is the single-layer, asymptotic-and-extrapolated space lower bound (loss 1); that is explicitly left to
cryptographer review, with the stacked-DRG hardening already identified if the margin proves thin.

---

## How to reproduce

```bash
bash experiments/run_c5.sh                        # self-test (31 pinned cells), then emit the CSV
python3 experiments/c5_comparison.py --self-test  # validate cells against source CSVs only
```

The self-test re-reads C1–C4/B2/B5 CSVs and asserts every numeric cell in this table still equals its
source (exact for byte/identity counts; ±1% for timings/fractions). If any upstream experiment is re-run
with different numbers, the self-test fails until this table is refreshed — so the capstone stays in sync
with the measurements it summarises. No Docker, stdlib only.
