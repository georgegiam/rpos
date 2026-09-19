# Phase 1 risk check — PoSpace DNS admission scheme

**Verdict.** The Proof-of-Space construction as written in the thesis (Chapter 6,
Algorithms 4–5) does **not** provide a space guarantee. The scheme labels a **hash
chain**, and a hash chain is a *path graph* — the least depth-robust graph there is.
Because of that, a prover can discard essentially all of the claimed storage and still
answer every challenge in time. We show this two ways, both confirmed on this machine:

- **v1 (thesis scheme, private-key chain).** The verifier cannot check a leaf's value, so a
  cheater commits to a tree of identical leaves, stores **~1 KB**, and passes **10000/10000**
  challenges while *claiming up to 4 TiB*.
- **v2 (our candidate fix, public-key chain + adjacency check).** Leaf-verifiability is
  restored, which kills the v1 attack — but the chain is still sequential, so a **checkpoint
  time–memory trade-off** lets a cheater store **~1.5/k** of the honest tree and recompute one
  *k*-length segment per challenge. Extrapolated to the thesis size (N = 3,355,443,200,
  ~200 GiB), **for every response timeout δ ∈ {0.1, 0.5, 1, 2, 5} s at which an honest node can
  answer at all, a cheater can also answer while storing at most ~1 MiB — parts per million of
  the honest storage.** No δ separates the two.

The design needs a **depth-robust** graph labelling (not a chain) to have any space guarantee.
Concrete options in §7.

---

## 1. Machine and method

All numbers below were produced on:

| | |
|---|---|
| CPU | **Apple M4**, 10 cores (Mac16,10), hardware SHA-256 (`FEAT_SHA256=1`, the ARM analogue of x86 SHA-NI) |
| RAM | 16 GiB |
| Disk | single internal **SSD** (Apple Fabric/NVMe); **no HDD** on this machine |
| OS / tools | macOS 26.6.2 (arm64); Python 3.11.5; Apple clang 21; OpenSSL 3.6.3 (Homebrew) |
| GPU | integrated Apple M4 GPU only; **no discrete GPU / hashcat** — parallel SHA-256 throughput **not measured** (see §8) |

**Sequential single-core SHA-256 chain rate: 20.36 MH/s** (median of 5×50 M-hash runs; 20.269–20.368,
[`results/chainrate.csv`](results/chainrate.csv)). This is the security-critical constant: it is how fast
*both* the honest prover and a cheater compute `h_i = H(h_{i-1} ‖ pk ‖ i)`. It is measured with a real
dependent chain in C, using a fetched-once `EVP_MD` and a reused `EVP_MD_CTX`
([`chainrate.c`](chainrate.c)) — the fast path on OpenSSL 3; the one-shot `SHA256()` and the deprecated
low-level API both dispatch through the provider per call and undercount the true per-core speed.

Everything is reproducible: see §9. Each script is standalone with a fixed seed.

---

## 2. Finding 0 — `rpos.py` plotting duplicates the chain (pre-existing bug)

`rpos.py` seeds every worker thread from the *same* initial hash, so an *n*-thread run emits the
same chain *n* times. Confirmed ([`check_rpos_threads.py`](check_rpos_threads.py)):

| threads | distinct hashes |
|---|---|
| 1 | 100% |
| 2 | 50% |
| 4 | **25%** |
| 8 | 12% |

The thesis was measured with `num_threads=4`, i.e. **only ~25% of the "plotted" file is unique
data**; the rest is three verbatim copies. This inflates the apparent plot throughput and means
the on-disk artefact is highly compressible — orthogonal to the attacks below, but it should be
disclosed, because it understates plotting cost and overstates the stored entropy.

---

## 3. Finding 1 — v1 is unconditionally broken (leaves are unverifiable)

In Algorithm 4 the chain uses the **private** key: `h_i = H(h_{i-1} ‖ k)`. The verifier holds only
`(root, pk)` and cannot recompute any leaf, so `VERIFYCHALLENGE` (Algorithm 5) checks *only* that the
supplied leaf and Merkle path hash to the committed root — it never constrains what the leaf *is*.

A cheater therefore commits to a tree whose leaves are all one constant `c`. Every node at a given
level is then identical, so **one hash per level** answers any challenge for any claimed size
([`attack_v1_constant_leaf.py`](attack_v1_constant_leaf.py), [`results/results_attack_v1.csv`](results/results_attack_v1.csv)):

| claimed size | cheater storage | challenges passed | response |
|---|---|---|---|
| 1 GiB (N=2²⁴) | 800 B | 10000 / 10000 | 8 µs |
| 256 GiB (N=2³²) | 1 056 B | 10000 / 10000 | 12 µs |
| 4 TiB (N=2³⁶) | 1 184 B | 10000 / 10000 | 11 µs |

This is not a trade-off, it is a total break: storage is **O(log N)** regardless of the claim. Any
usable PoSpace over a Merkle commitment must let the verifier check the *leaf value*, which is what
v2 attempts.

---

## 4. Finding 2 — v2 restores leaf-verifiability, but the chain still folds

**v2** ([`pospace.py`](pospace.py)) chains over the **public** key and the step index,
`h_i = H(h_{i-1} ‖ pk ‖ i)`, and a challenge *i* opens leaves *i−1* **and** *i*; the verifier checks
both Merkle paths **and** the adjacency `H(l_{i-1} ‖ pk ‖ i) = l_i`. This defeats the constant-leaf
attack: a leaf now has exactly one value consistent with its predecessor, and the verifier can test it.

But the leaves still form a **sequential chain**, and any chain label `h_j` is regenerable in ≤ *k*
steps from a checkpoint stored *k* positions back. So the cheater keeps, per segment of length *k*:

- one chain label at the segment start (a *checkpoint*), `32·N/k` bytes; and
- the Merkle levels from `log₂k` up to the root, `~64·N/k` bytes.

It **discards every leaf and the lower `log₂k` tree levels**. On challenge *i* it recomputes the
*k*-leaf segment(s) holding *i−1* and *i* (~*k* chain steps), rebuilds that subtree (~*k* hashes),
takes the lower siblings from the rebuilt subtree and the upper siblings from the stored levels
([`attack_v2_checkpoint.py`](attack_v2_checkpoint.py)). Every response verifies with the real
`verify_v2`.

### The measured trade-off

Storage is **≈ 1.5/k** of the honest full tree, **independent of N**, and response time is **O(k)**
([`results/results_v2_checkpoint.csv`](results/results_v2_checkpoint.csv); all five N collapse onto one
curve — [`results/fig_tradeoff.png`](results/fig_tradeoff.png)):

| k | cheater storage (of honest) | worst-case work | cheater response @ 20.4 MH/s | pass rate |
|---|---|---|---|---|
| 2⁴ | 9.375 % | 60 hashes | 0.003 ms | 100 % |
| 2⁸ | 0.586 % | 1 020 hashes | 0.050 ms | 100 % |
| 2¹² | 0.037 % | 8 190 hashes | 0.40 ms | 100 % |
| 2¹⁴ | 0.009 % | 32 766 hashes | 1.6 ms | 100 % |
| 2¹⁶ | 0.002 % | 131 070 hashes | 6.4 ms | 100 % |

For comparison, the **honest** prover reading real Merkle nodes from a tree file on the SSD (uncached
`pread`s, [`results/honest_disk.csv`](results/honest_disk.csv)) does `2·(log₂N+1) ≈ 42–50` random node
reads per challenge. The realistic uncached cost of that at scale is a few milliseconds (see the caveat
in §8). **The key point: at k = 2¹⁴–2¹⁶ the cheater's compute response (1.6–6.4 ms) is already in the
same range as — or faster than — the honest node's disk reads**, while storing 0.002–0.009 % of the data.

---

## 5. Finding 3 — no timeout δ separates honest nodes from cheaters (v2)

Theorem 6.1 assumes a cheater must recompute the **whole** tree, `t_recompute = O(N log N)`, and asks for
`t_store < δ < t_recompute`. The checkpoint attack collapses `t_recompute` to `O(k)`, and the cheater
**chooses k as large as the timeout allows**, minimising storage. The response budget is
`response = RTT + work`; the honest node must satisfy `RTT + t_disk ≤ δ`, the cheater
`RTT + t_cheat(k) ≤ δ`, with `t_cheat(k) ≈ 2k / rate` on the sequential critical path (the two opened
leaves sit in ≤ 2 independent segments, run on separate cores).

Extrapolated to **N = 3,355,443,200 (~200 GiB honest tree)** at the measured 20.36 MH/s
([`extrapolate.py`](extrapolate.py), [`results/results_extrapolation.csv`](results/results_extrapolation.csv),
[`results/fig_thesis_extrapolation.png`](results/fig_thesis_extrapolation.png)):

| δ | RTT | honest can answer? | largest k a cheater can use | cheater storage |
|---|---|---|---|---|
| 0.1 s | 50 ms | yes | 2¹⁸ | **1.17 MiB** (5.7 × 10⁻⁶) |
| 0.1 s | 150–300 ms | **no** (δ < RTT) | — | *honest fails too* |
| 0.5 s | 300 ms | yes | 2²⁰ | 0.29 MiB (1.4 × 10⁻⁶) |
| 1 s | 300 ms | yes | 2²² | 0.07 MiB (3.6 × 10⁻⁷) |
| 2 s | 50–300 ms | yes | 2²⁴ | 0.018 MiB (8.9 × 10⁻⁸) |
| 5 s | 50–300 ms | yes | 2²⁵ | 0.009 MiB (4.5 × 10⁻⁸) |

**Result: `separation = NONE` in every feasible row.** Whenever the honest node can meet δ, a cheater
can too, storing between ~1 MiB (tight δ) and ~9 KiB (loose δ) instead of 200 GiB — a factor of
**10⁵–10⁷** less. And because the cheater can always pick a *smaller* k to go faster, it never has to
sail close to the deadline. There is no δ that lets a 200 GiB honest node through while stopping a
cheater. The scheme provides **no space guarantee** for v2.

(Note also that both budgets are dominated by network RTT, not by SHA-256: even the honest disk read is
~1–5 ms « 50–300 ms RTT. Making the hash "heavier" would not help — it slows the honest prover equally.)

---

## 6. Finding 4 — segment-reset variant: even the adjacency check is porous

The checkpoint attack already wins with **zero** detection risk, so a cheater need do no more. For
completeness we also examined whether the adjacency check catches a cheater who keeps *nothing* — a
**segment-reset** prover that restarts the chain every *k* steps from a directly computable value
`H(pk ‖ s)`, storing no checkpoints ([`attack_v2_reset.py`](attack_v2_reset.py)).

The reset breaks the true chain at each segment boundary, so a challenge whose index is a multiple of
*k* fails the adjacency check. We **confirmed this against the real `verify_v2`**: boundary challenges
are caught 1023/1023, and random challenges are detected *iff* `i ≡ 0 (mod k)`. The per-challenge
detection probability is `p₁ = (N/k − 1)/(N−1) ≈ 1/k`; with *c* challenges per round the detection
probability is `1 − (1 − p₁)^c` ([`results/results_v2_reset.csv`](results/results_v2_reset.csv),
[`results/fig_reset_detection.png`](results/fig_reset_detection.png); Monte-Carlo matches analytic):

| k | c=1 | c=10 | c=50 | c=100 |
|---|---|---|---|---|
| 2⁶ | 1.6 % | 14.6 % | 54.5 % | 79.3 % |
| 2¹⁰ | 0.10 % | 1.0 % | 4.8 % | 9.3 % |
| 2¹⁴ | 0.006 % | 0.06 % | 0.3 % | **0.6 %** |

So even the probabilistic defence is weak: at k = 2¹⁴ a reset cheater survives a round of 100 challenges
99.4 % of the time while storing ~1/k. This is a *strictly worse* attack for the cheater than the
checkpoint attack (it adds risk for no storage benefit), but it shows the adjacency check only samples
`~1/k` of the boundaries — it does not certify the chain.

---

## 7. Why this happens — a hash chain is not depth-robust

Proofs of Space get their guarantee from labelling a **depth-robust** directed acyclic graph. A DAG is
`(e, d)`-depth-robust if deleting any *e* vertices still leaves a directed path of length *d*. The
security argument is a pebbling/graph-labelling one: after the prover deletes labels to save space, a
random challenge forces it to recompute a path through the graph, and depth-robustness guarantees that
*no matter which e labels it keeps*, some challenge needs a long (≥ d) sequential recomputation
[DFKP15, ABP17]. Space is then genuinely traded for time.

A **hash chain is the path graph `0 → 1 → … → N−1`** — the *opposite* of depth-robust. Deleting a single
vertex disconnects it; keeping every *k*-th vertex lets you regenerate any label in ≤ k steps. Its
cumulative pebbling complexity is trivial. That is exactly the checkpoint attack, and it is why the
`1.5/k` trade-off exists for *any* k, at *any* N. The v2 adjacency check verifies *local* correctness of
the chain but does nothing about its *graph structure*, so it cannot help. **No amount of leaf-checking
or timeout tuning fixes a chain; the graph has to change.**

---

## 8. Candidate fixes

Three options, from "keep the architecture, fix the labelling" to "adopt a known-good scheme" to
"reframe the claim honestly".

### Fix A — Merkle commitment over a depth-robust graph labelling *(recommended)*

Replace the chain with a labelling of an `(e, d)`-depth-robust graph (or a stacked construction), keep
the Merkle-tree commitment and the same challenge/verify shape (open a node **and its graph parents**;
the verifier checks the label = H(parents) and the paths). Practical instances: **stacked expanders**
(Ren & Devadas, TCC 2016 [RD16]); **stacked depth-robust graphs (SDR)** as used in Filecoin's proof of
replication (Fisch, EUROCRYPT 2019 [Fis19]); practical DRG parameters in [ABH17].

- **Pros:** restores a real space lower bound (this is the standard, peer-reviewed way to build PoSpace);
  reuses your Merkle/DHT plumbing and per-challenge Merkle-path verification; storage/time trade-off
  becomes provably bounded rather than `1.5/k`.
- **Cons:** plotting is heavier (each label hashes *in-degree* parents, and stacked constructions do
  multiple layers); challenge responses open more nodes (all parents), so proofs and verify cost grow;
  choosing sound `(e,d)` parameters and in-degree is fiddly and must cite/replicate published parameters.
- **Effort:** **high.** New plotting code (graph generation + layered labelling), a parent-aware
  challenge/verify, and a parameter study. This is a research-grade change, but it is the only one that
  makes the *original claim* ("admission requires real space") true.

### Fix B — adopt Chia's Proof of Space and accept its cost

Chia does not use a chain; it stores tables for a sequence of functions and answers challenges by
producing a proof-of-inverse, a design explicitly built to resist Hellman-style time–memory trade-offs
[AACKPR17], deployed in [CP19].

- **Pros:** mature, audited, widely deployed; strong TMTO resistance is the whole point of the design;
  removes the need to invent and defend your own construction.
- **Cons:** substantially more complex plotting and larger, more intricate proofs than a Merkle path;
  heavier verifier; importing it wholesale weakens the thesis's novelty claim (the contribution becomes
  the DNS/DHT application, not the PoSpace).
- **Effort:** **high** (integration + re-benchmarking), but lower *research* risk than Fix A since the
  primitive is off-the-shelf.

### Fix C — reframe the scheme honestly as what it is *(lowest effort, defensible)*

Keep the chain construction but stop claiming a space guarantee. State plainly, with these numbers, that
v1/v2 is a **proof of one-time sequential computation with a checkpoint time–memory trade-off**, not a
proof of *persistent* space, and scope the security claim accordingly (e.g. Sybil cost = the one-time
plot, not ongoing storage; note the `1.5/k` trade-off and that no δ separates honest from cheater).

- **Pros:** immediately consistent with the evidence; directly answers the examiners' "what is lost by
  gaining efficiency" — you gained a cheap Merkle-path verify and lost the space guarantee; small writing
  effort; the measured trade-off and figures here become a contribution.
- **Cons:** the admission mechanism no longer resists a storage-cheating adversary, so its usefulness for
  Sybil resistance in the DNS resolver is much weaker and must be argued on other grounds (or combined
  with another mechanism).
- **Effort:** **low** (writing + honest scoping). Best paired with Fix A/B as future work.

**Recommendation:** if the space guarantee is load-bearing for the thesis, do **Fix A** (or **B**);
either way, use **Fix C**'s framing now so the thesis claims match the evidence.

---

## 9. Reproducing these results

```
cd phase1
# Part 1: confirm the two existing checks
python3 check_rpos_threads.py
python3 attack_v1_constant_leaf.py           # -> results/results_attack_v1.csv (moved)
# Part 2: environment + sequential chain rate (builds ./chainrate)
cc -O3 -mcpu=native -isysroot $(xcrun --sdk macosx26.5 --show-sdk-path 2>/dev/null || \
   echo /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk) chainrate.c -o chainrate \
   -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lcrypto
python3 measure_env.py                        # -> results/env.csv, results/chainrate.csv
# Part 3: checkpoint attack + honest on-disk baseline (writes/deletes tree files up to ~1 GiB)
python3 attack_v2_checkpoint.py               # -> results/results_v2_checkpoint.csv, honest_disk.csv
# Part 4: extrapolation to the thesis size
python3 extrapolate.py                        # -> results/results_extrapolation.csv
# Part 5: segment-reset detection
python3 attack_v2_reset.py                    # -> results/results_v2_reset.csv
# Part 6: figures
python3 plots.py                              # -> results/fig_*.png
```

Note on the C build: the default macOS SDK (27.0) ships a `.tbd` this machine's `ld` cannot parse, so we
compile against SDK 26.5 (both are present under CommandLineTools). `rpos.py` is unchanged.

---

## 10. Caveats / threats to validity

- **Honest disk time is a lower bound at small N.** With `F_NOCACHE` set, files that fit in the 16 GiB
  page cache still read at RAM speed (the sub-30 µs figures for N ≤ 2²³ are effectively cached); only the
  1 GiB N=2²⁴ tree shows device-like latency (~16 µs/read). At the true 200 GiB scale nothing is cacheable,
  so §5 uses a **conservative 80 µs/read (≈5 ms/response)** for the honest side. The conclusion is
  insensitive to this: honest disk time (1–5 ms) is dwarfed by network RTT (50–300 ms), and the cheater
  can match either.
- **Single core, single machine.** The 20.36 MH/s rate is one M4 core with hardware SHA-256. A cheater
  with a faster core or more cores only does *better* (larger k, less storage), so using this rate is
  conservative for the defender. The chain is inherently sequential, so **GPU parallelism does not help a
  cheater recompute a segment** — which is why not measuring the GPU (no hashcat/discrete GPU here) does
  not affect the finding.
- **Python simulation vs native attacker.** The attack scripts run in Python; response *times* in §4–5 are
  reported at the measured **native** C rate (`nhash / rate`), which is what a real cheater achieves, not
  Python wall-clock. Pass/verify correctness is checked with the actual `verify_v2`.
- **No HDD.** The honest-vs-cheater comparison is on SSD only (this machine has no HDD). An HDD would make
  the *honest* node slower (~7 ms/seek → ~0.5 s/response), which *widens* the cheater's advantage.

---

## 11. References

- **[DFKP15]** S. Dziembowski, S. Faust, V. Kolmogorov, K. Pietrzak. *Proofs of Space.* CRYPTO 2015.
- **[RD16]** L. Ren, S. Devadas. *Proof of Space from Stacked Expanders.* TCC 2016.
- **[Fis19]** B. Fisch. *Tight Proofs of Space and Replication.* EUROCRYPT 2019. (Filecoin stacked-DRG PoRep)
- **[ABP17]** J. Alwen, J. Blocki, K. Pietrzak. *Depth-Robust Graphs and Their Cumulative Memory
  Complexity.* EUROCRYPT 2017.
- **[ABH17]** J. Alwen, J. Blocki, B. Harsha. *Practical Graphs for Optimal Side-Channel Resistant Proofs
  of Space.* ACM CCS 2017.
- **[AACKPR17]** H. Abusalah, J. Alwen, B. Cohen, D. Khilko, K. Pietrzak, L. Reyzin. *Beyond Hellman's
  Time-Memory Trade-Offs with Applications to Proofs of Space.* ASIACRYPT 2017. (basis of Chia's PoSpace)
- **[CP19]** B. Cohen, K. Pietrzak. *The Chia Network Blockchain.* 2019.
- **[Hel80]** M. Hellman. *A Cryptanalytic Time-Memory Trade-Off.* IEEE Trans. Information Theory, 1980.
