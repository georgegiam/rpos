# PhD thesis amendments — decentralized DNS resolver with Proof of Space

This repo holds the work for a **major-corrections resubmission** of a PhD thesis on a
decentralized DNS resolver that uses **Proof of Space (PoSpace)** for Sybil-resistant node
admission over a **Chord DHT**. The examiners rejected the first round of amendments. This
file is the single source of truth for *what* the examiners asked, *how* we plan to answer
it, and *where we currently are*. Read it fully before doing anything.

**Deadline:** revised thesis + response letter due **13 April 2027**. Internal target
**26 March 2027** (≈2 weeks buffer).

---

## 1. What the examiners require

Three points must all be answered. Every experiment and chapter edit traces back to one of
these:

- **(i) Security comparison: Chia PoSpace vs the proposed PoSpace.** A detailed, row-by-row
  comparison, explicitly including *"what is lost by gaining efficiency"* — i.e. what
  security the proposed scheme trades away for its lower cost. → **Phase 8**.
- **(ii) Experimental / simulation validation of the full system**, including analysis of
  **malicious scenarios** (not just the happy path). → **Phases 2–7**.
- **(iii) Performance analysis**: **latency, throughput, and scalability** of the whole
  resolver — not just PoSpace plot initialization, which is all the thesis currently
  measures. → **Phases 5–6**.

---

## 2. Ground rules for any session working in this repo

- **Never modify `rpos/rpos.py`.** It is the exact code the thesis was benchmarked with; it
  must stay byte-identical so results remain reproducible/defensible. Its known threading
  bug (below) is *documented*, not fixed. New code goes in new files.
- **Measure, don't assert.** Every number that will enter the thesis must come from a script
  in this repo with a fixed seed and a CSV in `results/`, or from a citation. No estimates in
  prose.
- **Data-independent, reproducible constructions.** Anything cryptographic must be
  reconstructible bit-for-bit from public inputs (e.g. `pk`) so a verifier/examiner can
  re-run it.
- **Flag, don't hide, the soft spots.** Asymptotic-vs-measured gaps, parallel-attacker
  assumptions, and any parameter awaiting sign-off are stated openly. An examiner will find
  them otherwise.
- **Cryptographic parameters need supervisor / cryptographer sign-off** before any *final*
  thesis claim (see Phase 1 status).

---

## 3. Current status snapshot  (update this section as work progresses)

| Phase | Title | Status |
|---|---|---|
| 0 | Preparation | **done** — repo exists (rpos cloned, `phase1/` added); supervisor meeting held, compute access secured, folder scaffold created, thesis inconsistencies fixed |
| 1 | PoSpace risk check | **done** — see below |
| 2 | Build resolver node | **done** — epic #17 (all 8 sub-issues); see below |
| 3 | Build testbed | **done** — N=32 emulation reliable (97.7% success, median hops 3, full finger convergence); Unbound baseline collected; N=64 deferred to Phase 5 simulator (testbed resource limit, not a protocol bug — see Phase 3) |
| 4 | Sanity checks + baseline | **done** — hops match Chord theory (+0.5), Unbound baseline collected, N=32 stable over 3 runs, parameters frozen; see `results/PARAMETERS.md` |
| 5 | Simulator for large scale | not started |
| 6 | Performance experiments | not started |
| 7 | Attack experiments | not started |
| 8 | PoSpace security comparison (Chia) | not started |
| 9 | Writing | not started |
| 10 | Resubmit | not started |

### Phase 1 outcome (the design-changing result)

The risk check found the thesis PoSpace scheme is **not sound**, and a fix was adopted:

- **v1 (thesis scheme, Algorithms 4–5):** labels a hash chain keyed by the prover's
  **private** key, so the verifier can never check a leaf value. A **constant-leaf attack**
  lets a cheater store ~1 KB and pass 100% of challenges. **Broken.**
- **v2 (first fix — public-key chain + adjacency check):** verifiable leaves, but the
  labelling graph is still a **path (hash chain)**. A **checkpoint time–memory trade-off**
  lets a cheater store parts-per-million of the plot and still answer in time. **No response
  timeout δ separates honest from cheater.** Broken.
- **Root cause:** a hash chain is a path graph; Proofs of Space need a **depth-robust graph
  (DRG)** so that discarding labels forces an Ω(N) recompute (Dziembowski–Faust–Kolmogorov–
  Pietrzak, CRYPTO 2015).
- **Fix adopted — v3 (Fix A):** replace the chain's labelling graph with **DRSample**
  (Alwen–Blocki–Harsha, CCS 2017). Keep the Merkle commitment, signatures, DHT, and
  challenge/verify shape unchanged. Label `l_i = H(pk ‖ i ‖ ⧺ parent labels)` over the DRG
  parents; a challenge opens node *i* **and all its DRG parents**, each with a Merkle path.
  - **Result:** a real space lower bound is restored. The retention attack now costs
    ~10⁶ hashes regardless of storage (≈930× the chain at matched storage), and a **usable δ
    exists** at thesis scale (back-cone ≈0.45·N → ~75 s recompute vs a ≤5 s timeout).
  - **Cost:** proofs grow to 1.8–6.5 KiB (linear in in-degree δ); verify tens of µs; native
    plot of 100 GiB in ~3–7 min.
  - **Open — needs sign-off before Chapter 6:** the separation rests on the *measured*
    back-cone fraction extrapolated ~800× beyond the measured range (relies on DRSample's
    asymptotic guarantee, not a re-proof); and an unlimited-core parallel attacker makes the
    loosest δ=5 s marginal. **Choice of δ (in-degree), target depth-robustness, and whether a
    stacked DRG is needed → supervisor/cryptographer.**

**Design is provisionally frozen on v3 DRG**, pending that sign-off.

Phase 1 artifacts live in `phase1/`: `FINDINGS.md` (the two breaks, with measurements),
`FIX_A.md` (the DRG fix, before/after, costs, caveats), `pospace.py` / `pospace_drg.py` /
`drg.py`, the attack scripts, and `phase1/results/` (CSVs + figures, incl.
`fig_money.png/.pdf`, the before/after "money plot").

---

## 4. The full plan

Target submission **26 Mar 2027**; buffer to **13 Apr 2027**. Each phase has a "done when".

### Prerequisites to gather first
- **People/access:** supervisors' agreement on the approach (emulation + calibrated
  simulation); compute (one 32+ core / 64+ GB machine, or cloud VMs, or Iridis HPC);
  optionally a GPU box for PoSpace attack tests.
- **Software (all free):** Python 3.11+ (`asyncio`, `dnslib`/`dnspython`, `cryptography`,
  `pandas`, `matplotlib`, `simpy`); Docker + Compose; Linux `tc netem`; NSD/BIND/CoreDNS for a
  local DNS hierarchy; Unbound (baseline resolver); `dnsperf`/`resperf`; Git.
- **Data:** Tranco top-sites list; a public internet-latency dataset (fixed delays as
  fallback); optionally a real DNS query trace.

### Phase 0 — Preparation
- [ ] Meet supervisors; agree plan, scope, target date.
- [ ] Ask the graduate school whether scope may be clarified with examiners (e.g. "emulation
      at a few hundred nodes + calibrated simulation acceptable?"). Optional but de-risks.
- [ ] Secure compute access.
- [ ] Create repo folders: `node/`, `testbed/`, `sim/`, `attacks/`, `experiments/`, `results/`.
- [ ] Fix known thesis inconsistencies now: 1.38 h vs 1h38m vs 1.64 h; the 300 GiB figure;
      the swapped Figure 6.4/6.5 references.
- **Done when:** supervisors approve the plan, compute is available, repo exists.

### Phase 1 — PoSpace risk check *(done — see §3)*
- [x] Adversary storing every *k*-th chain hash + top Merkle levels; recompute on challenge.
- [x] Measure cheater vs honest response time across *k* at full plot size.
- [x] Decide: cheaters not separable → **designed and implemented a fix (v3 DRG)**, re-measured.
- **Done when:** you know whether δ separates honest from cheater, and the PoSpace design is
  frozen. → δ separation restored under v3; design provisionally frozen pending sign-off.

### Phase 2 — Build the resolver node  *(answers (ii))*  *(done — code in `node/`)*
Built and tested with 5 local nodes. Transport is **in-process (asyncio queues)**, not real
sockets — real networking (and hence `dig` over UDP) is deferred to Phase 3 by design. The v3
DRG scheme is **imported** from `phase1/pospace_drg.py` (not copied); `rpos/rpos.py` untouched.
1. [x] Chord basics: `join`, `find_successor`, `stabilize`, `fix_fingers`, successor list. → `node/chord.py`
2. [x] Chunk storage: domain→chunk mapping; replicate each chunk to *s*=3 successors. → `node/storage.py`
3. [x] DNS interface: real wire-format DNS A queries/responses via dnspython. → `node/dns_interface.py`
       *Caveat:* parsed/served in-process, **not yet bound to a UDP socket, so `dig` does not work
       until Phase 3.*
4. [x] Query path (Algorithm 2): find responsible node; fetch from primary + replicas;
       majority vote. → `node/query.py`
5. [x] Fallback: iterative resolution (stubbed hierarchy) then store the result back in the DHT. → `node/query.py`
6. [x] Chunk ledger (Algorithm 3): propose → pre-commit → majority commit; hash-chained log. → `node/ledger.py`
7. [x] TTL refresh: expired records trigger an update through the ledger. → `node/ledger.py`
       *Known gap:* only records committed **through the ledger** are TTL-tracked; records written by
       the query fallback's `store_chunk` bypass the ledger and are **not** refreshed. Unifying the
       two write paths is deferred (originally pointed at #16, which did not pick it up) — track in
       Phase 3/6 before A5 (updates/ledger growth) relies on it.
8. [x] PoSpace admission + periodic challenges: configurable plot size, timeout δ=2 s, evict after
       3 consecutive fails; **v3 DRG** scheme from Phase 1. → `node/pospace_admission.py`
9. [x] Logging: one CSV line per query and per update. → `node/results/queries.csv`, `updates.csv`
10. [x] Malicious-mode hooks: config flag honest / lie / drop / misroute / forge, inert by default;
        behaviours land in Phase 7. → `node/malicious.py`
- **Done when:** 5 nodes resolve correctly, survive a node leaving, commit updates, log all. →
  **met.** Integration test (`node/integration_test.py`) green; `node/tests/` suite **9 passed**
  (incl. `test_majority_vote.py` — a lying replica is outvoted — and `test_pospace_eviction.py` —
  a node failing 3 challenges is evicted and the ring heals).

### Phase 3 — Build the testbed  *(answers (ii)/(iii))*  *(in progress — epic #24; code in `testbed/`, `node/`)*
- [x] Local DNS world in containers: NSD root + com/org TLDs + 2 authoritative servers; zones for
      1000 Tranco domains with realistic TTLs (300–3600 s). → `testbed/dns/`
- [x] Docker Compose/script to start N resolver nodes automatically. → `testbed/docker-compose.yml`, `up.sh`
- [x] `tc netem` delays between containers (two-tier: 5 ms same-region / 50 ms cross-region). → `testbed/netem.sh`
- [x] Unbound against the same hierarchy and delays. → `testbed/unbound/`
- [x] Query generator with Zipf popularity (α=1.0). → `testbed/query_gen.py`
      *Note:* uses a built-in dnspython query loop, **not** `dnsperf`/`resperf`.
- [x] One-command end-to-end experiment: start → warm up → load → collect CSVs → shut down. → `testbed/run_experiment.sh`
- [x] **Real socket transport so nodes form a Chord ring across containers** (the Phase-2-deferred
      networking). Added **alongside** the in-process bus, selected by config:
      `node/socket_net.py` (TCP RPC, **data-only codec + frame cap + keep-alive pool + IP addressing +
      consecutive-failure liveness**), `node/run_ring_node.py`
      (create/join over sockets + UDP DNS front end + maintenance loop),
      `testbed/gen_nodes_compose.py` (N-node ring compose). `run_experiment.sh --mode nodes`
      routes queries to the ring; `--mode host` keeps the Unbound baseline. All Chord/storage/
      ledger/PoSpace RPCs now travel over the wire; protocol logic is byte-identical to Phase 2.
- [x] Scale-up test: largest reliable N. *(Reliable emulation ceiling is **N=32**; N=64 is
      deferred to the Phase 5 simulator — the N=64 shortfall is a testbed resource limit, not a
      protocol bug, see the residual-wall note below.)*
- **Done when:** one command runs a full experiment and produces results files. → **DONE at the
  N=32 emulation ceiling.** Decision (this session): **N=32 is accepted as the emulation scale**;
  large N (1,000–10,000) is answered by the Phase 5 simulator, calibrated against N=8/N=32. The
  examiners asked for experimental validation, not a specific node count. nodes-mode is real
  (`resolver_used=node-<id>`); host-mode is the Unbound baseline. Measured results (netem on,
  10 qps, 30 s), flagged not hidden:
  - **N=8: 100.0%** (300/300), hops median 1–2, p50 ~290 ms.
  - **N=32: 97.7%** (293/300), **ring fully converged (32/32 correct successors, 0 orphans)**,
    hops median 3 (≈½·log₂32), p95 1.5 s.
  - **N=64: ~15–34%** across runs; the ring converges only to ~30–44/64 correct successors and
    does not heal. **Deferred to the Phase 5 simulator** (testbed resource limit, not a protocol
    bug — see the residual-wall note); not blocking Phase 3.

  **N=64 root cause — a chain diagnosed this session (each step measured, not asserted):**
  1. *Finger staleness.* `chord.py` `fix_fingers` refreshes 1 of M=160 slots/round; only the top
     ~log₂N fingers matter and they converged last → O(N) successor-walks. **Fixed** in Phase-3
     code (`run_ring_node._refresh_top_fingers`, chord.py untouched): hops dropped to median ~3.
  2. *Connection-per-RPC latency.* Every RPC opened a fresh TCP connection; over netem that is a
     handshake per hop. **Fixed** with a keep-alive connection pool in `socket_net.py` (N=8:
     96.7%→**100%**, p50 879→~290 ms).
  3. *`is_up` over-eagerness.* The liveness cache marked a peer down on the FIRST failed RPC;
     chord.py's stabilize/notify then reject good peers. In-process a 2% transient-failure rate
     with mark-down-on-1 orphans 62/64 nodes; requiring **3 consecutive** failures drops that to
     5/64. **Fixed** (`SocketNetwork.fail_threshold`).
  4. *Docker embedded DNS.* Roster peers were Docker service names, re-resolved on EVERY connect;
     under the startup connection storm the embedded DNS stalls ~2 s or fails 1–3% of lookups —
     measured: connect-by-hostname 1–3% fail/2 s stall vs **connect-by-IP 0% / 0.2 ms**. **Fixed**
     by addressing peers by the compose's static IPs (`RING_IP_PREFIX`/`RING_IP_BASE`), plus an
     IP cache + connect-retry in `socket_net.py`.
  5. *Concurrent-join star.* All N nodes joined the seed at once → a giant star stabilize must
     untangle over ~O(N) rounds. **Mitigated** with staggered joins (`JOIN_STAGGER`); at N=64 this
     drove `pred=None` to 0 but did not finish successor convergence.
  - **Residual wall (why N=64 still fails, honestly):** `find_successor` traffic — from queries
    AND finger maintenance — shares the event loop with `stabilize`, and `chord.py`'s stabilize
    **drops its successor on any RPC that misses its 2 s timeout**. At N=64 the bigger star needs
    more convergence rounds, during which the lookup traffic perturbs stabilize enough that the
    cycle never fully closes; the query load then re-perturbs it. The clean fix is to make
    stabilize tolerant of a transient timeout (retry / don't drop on first miss) — but that lives
    in **`chord.py`, which is frozen (Phase 2)**. Options needing a decision: (a) allow a
    minimal, documented robustness tweak to chord.py's stabilize; (b) run ≤32 nodes/host and reach
    N=64+ by combining emulation (≤32) with the Phase-5 simulator; (c) a separate maintenance
    event loop/process. **Not** raising the 5 s query timeout (that masks, not fixes).
  - **All the fixes above are net-positive and kept** — they took N=8 to 100% and made N=32 fully
    converge; they are not reverted for N=64's sake. Diagnostics kept: `debug_state` RPC +
    `testbed/finger_probe.py`.
  - **Distributed PoSpace eviction is still a stand-in** (`_evict` can't stop a remote node over
    sockets); honest nodes never trigger it, but Phase 7 needs consensus eviction.
  - **Transport hardened (STEP 1, committed separately):** pickle removed in favour of a length-
    prefixed **type-tagged JSON data-only codec** (decoder builds only fixed primitives; big
    160-bit ids exact, tuples≠lists, bytes base64) + a hard **8 MiB frame cap** rejected before the
    body is read. Closes the transport as a Phase-7 attack surface. See `node/socket_net.py`.
  - Per-run CSVs are git-ignored (seed-reproducible per §2); `experiments.csv` keeps the summary row.

### Phase 4 — Sanity checks + baseline  *(done — see `results/PARAMETERS.md`)*
- [x] Measured hop counts vs Chord theory (≈½ log₂N); mismatch = bug. → N=8: theory 1.5,
      measured median 2 (+0.5); N=32: theory 2.5, measured median 3 (+0.5). Both well under the
      1.5-hop bug threshold → routing matches Chord, no bug.
- [x] Unbound baseline: latency and max queries/sec. → reference (10 qps) p50 3.5 / p95 132.9 /
      p99 214.9 ms; **max sustained ≥99% = 200 qps** (100.0%), drops to 96.7% at 400 qps, so
      saturation is between 200–400 qps. Raw: `results/baseline_unbound.csv`. (Not pushed past
      400 qps: at ≥800 qps the closed-loop generator, not Unbound, is the bottleneck.)
- [x] Repeat one run 3–5× for stability. → N=32 ×3: 99.3% / 100% / 100%, p50 524.5 / 491.9 /
      511.7 ms (success spread <10%, p50 spread <2×) → **stable**; hop median 3 every run.
- [x] Freeze parameter defaults (s, δ, delays, workload) and write them down. →
      `results/PARAMETERS.md` (s=3, δ=2 s, 5/50 ms two-tier, 5 s query timeout, MAINT 1.0 s,
      finger refresh ~4 s, challenge ~5 s, Zipf α=1.0 / 1000 domains, warm-up 30 s, seed
      20260919, N=32 ceiling).
- **Done when:** numbers are stable, sensible, and the baseline exists. → **met.**

### Phase 5 — Simulator for large scale  *(answers (iii))*  *(runs in parallel, Dec–mid-Jan)*
> **Calibration note:** the simulator must be calibrated against **N=8 and N=32** emulation
> results before scaling to N=1,000+. The emulation ceiling is **N=32** due to testbed resource
> limits (find_successor traffic starves stabilize at N=64); this is a known harness limitation,
> not a protocol issue. So the simulator carries the large-N (incl. N=64) scaling evidence.
- [ ] SimPy model of the same protocol, reusing protocol logic where possible.
- [ ] Calibrate with per-hop processing times and message sizes measured in emulation.
- [ ] Validate: at N=8 and N=32 the simulator must closely match emulation (report the match),
      then check N=64 in-sim behaves as theory predicts.
- [ ] Scale to N = 1,000 / 5,000 / 10,000.
- **Done when:** simulator matches emulation at N=8/N=32 and runs at 10k nodes.

### Phase 6 — Performance experiments  *(answers (iii))*
Run each 3–5×; report averages with error bars and percentiles.
- [ ] **A1 Latency vs N:** p50/p95/p99, split by cache hit / DHT hit / fallback, vs Unbound.
- [ ] **A2 Throughput:** raise load to saturation, several N.
- [ ] **A3 Scalability:** throughput and per-node load as N grows (emulation + simulation).
- [ ] **A4 Replication cost:** s = 3, 5, 7.
- [ ] **A5 Updates:** commit latency, messages per update, ledger growth.
- [ ] **A6 Churn:** lookup success and availability vs session length.
- [ ] **A7 Admission:** join time vs plot size.
- **Done when:** a plot/table per experiment, each with an interpreting paragraph.

### Phase 7 — Attack experiments  *(answers (ii))*
- [ ] Experimental threat-model table: adversary fraction f = 0–50%; colluding vs
      independent; random vs targeted placement; each attack mapped to Tables 4.1 / 4.2.
- [ ] Implement malicious behaviours; run each attack across f:
  - [ ] **B1 Tampering/poisoning:** % forged answers accepted vs the theoretical bound.
  - [ ] **B2 Targeted placement:** cost to capture a chunk majority; can node IDs be ground?
  - [ ] **B3 Censorship:** success rate + latency for blocked domains.
  - [ ] **B4 Routing/eclipse:** lookup success + extra hops.
  - [ ] **B5 Sybil:** identities and chunk control for a given storage budget.
  - [ ] **B6 Malicious proposer:** rejection rate + time to eviction.
  - [ ] **B7 DoS:** effect on everyone else.
- **Done when:** every attack has a setting, a metric, and a result graph.

### Phase 8 — PoSpace security comparison (Chia)  *(answers (i))*  *(parallel, Feb–7 Mar)*
- [ ] **C1:** final partial-storage attack results on the frozen (v3) design.
- [ ] **C2:** δ under realistic network jitter → false-reject / false-accept rates.
- [ ] **C3:** detection probability vs challenges per round.
- [ ] **C4:** proof size and prover/verifier time, measured against Chia.
- [ ] **C5:** full Chia-vs-proposed comparison table, each row backed by a measurement or
      citation — **including the "what is lost by gaining efficiency" discussion.**
- **Done when:** the comparison table is complete and the "what is lost" discussion is written.

### Phase 9 — Writing
- [ ] New chapter **"Experimental Evaluation"** replacing Section 6.5: testbed + methodology
      (reproducible), experimental threat model, results for Parts A/B/C, limitations.
- [ ] Update abstract, Chapter 1 contributions, Chapter 6 (Table 6.4), and Conclusions.
- [ ] Public code repo referenced in an appendix.
- [ ] Response-to-examiners letter: quote each of the three points, reply with exact section /
      figure / table numbers.
- [ ] Supervisor review, then final proofread.
- **Done when:** supervisors sign off.

### Phase 10 — Resubmit
- [ ] Submit revised thesis + response letter (by 26 Mar; buffer to 13 Apr).

---

## 5. Key technical facts

- **Benchmark machine:** Apple M4, 10 cores, 16 GiB RAM. **Sequential SHA-256 chain rate:
  20.36 MH/s** single-core (median of 5 runs). This constant underpins every timing claim.
- **Thesis plot scale:** N = 3,355,443,200 leaves (~200 GiB of 32-byte labels; "100 GiB"
  and "300 GiB" both appear in the thesis — an inconsistency to fix in Phase 0).
- **`rpos.py` threading bug (documented, not fixed):** all threads start from the same
  initial hash, so a 4-thread plot is ~75% duplicate data. The old "1h38m" plot benchmark is
  therefore invalid and must be **re-measured** before any speedup is claimed. See
  `phase1/FINDINGS.md` Finding 0.
- **Scheme versions:** v1 = thesis (broken), v2 = simple fix (broken), **v3 = DRG (adopted)**.
- **DRG construction:** DRSample bucket method; in-degree δ swept over {2, 4, 8}; parents
  derived from `SHA-256(pk ‖ "drg" ‖ i ‖ edge_index)` (data-independent, verifier-reproducible).

## 6. Repo layout (target)

```
rpos/rpos.py        # ORIGINAL thesis plotter — do not modify
phase1/             # Phase 1 risk check (done)
  FINDINGS.md       # the two security breaks, with measurements
  FIX_A.md          # v3 DRG fix: before/after, costs, caveats
  pospace.py        # v1 + v2 reference implementations
  pospace_drg.py    # v3 DRG scheme
  drg.py            # DRSample DAG + reproducibility tests
  attack_*.py       # retention / constant-leaf attacks
  results/          # CSVs + figures (fig_money.*, etc.)
node/ testbed/ sim/ attacks/ experiments/ results/   # Phases 2–8 (to create in Phase 0)
```

## 7. Supervisor checkpoints

| Date | Checkpoint |
|---|---|
| Mid-Oct 2026 | PoSpace risk-check result |
| End Nov 2026 | Node working |
| Mid-Jan 2027 | Testbed + baseline done; simulator validated |
| Early Feb 2027 | Performance results |
| Early Mar 2027 | Attack + security results |
| Late Mar 2027 | Full draft |

**If any checkpoint slips by >2 weeks, cut scope.** Drop the simulator's largest sizes, or
attack B7, before anything else.
