# B1 — Tampering / cache poisoning: methodology notes (issue #42, Phase 7, examiner point (ii))

Reproducible trail for the B1 attack experiment. Numbers live in
[`B1_tampering.csv`](B1_tampering.csv) and [`fig_B1_tampering.png`](fig_B1_tampering.png); this file
records *how* they are produced and the honest caveats (CLAUDE.md §2 "measure, don't assert" /
"flag, don't hide").

## What B1 measures
A fraction **f** of the **N=32** ring runs **malicious** (`MALICIOUS_MODE=lie` →
`node/malicious.py::_h_get_chunk` returns the forged A-record **`6.6.6.6`** on every replica read).
B1 measures the **% of forged answers accepted by clients** — a client reply whose A record differs
from the ground-truth `answer_ip` — swept over f, and compares it to the **majority-vote bound**.

The *intended* defence is the **s-replica plurality vote** (`node/storage.py::get_chunk`,
`Counter(values).most_common(1)`): a forged value should be accepted for a chunk only when
**≥ ⌈(s+1)/2⌉ = 2 of its s=3 replicas lie**, so the attack should track `3f²−2f³`.

### Headline finding — the vote achieves only ≥1-of-s, not ≥2/3
**Measured forged-acceptance tracks `1−(1−f)³` (a SINGLE malicious replica suffices), far above the
intended `3f²−2f³`.** The honest control (f=0 → 0% forged, votes almost all `3/3`) proves this is
caused by the adversary, not by cold-start or `chord.py` fragility. Two reinforcing mechanisms in
`node/storage.py::get_chunk` break the majority vote:

1. **Honest replicas abstain; the vote skips them.** `get_chunk` appends a replica's value only
   `if v is not None`. A `lie` node returns `6.6.6.6` for **any** chunk — *including one it never
   stored* — while honest replicas that don't (yet) hold that chunk return `None` and are **dropped
   from the tally**. So `most_common` is taken over *responders only*: one liar + two abstaining
   honest nodes = a **`1/1` forged "majority"**. The liar is never outvoted.
2. **The fabricated reply suppresses the honest write-back.** Because the forged value is non-`None`,
   the query is a `dht_hit`, so it **never falls back** to the honest upstream and therefore the
   chunk is **never honestly stored** on its replicas. Any chunk whose replica set contains **≥1**
   malicious node is thus permanently forgeable — not a transient cold-start effect (it persists
   through warm-up and maintenance, since the honest value can never get written).

Net: the achieved bound is **`P(≥1 of s replicas malicious) = 1−(1−f)ˢ`**, not
`P(≥⌈(s+1)/2⌉) = 3f²−2f³`. At s=3 that is 25.6 / 46.4 / 67.5 / 79.1 / 87.5% across the f grid versus
the intended 2.5 / 9 / 23 / 36 / 50%. The measured in-process curve sits **cleanly on** the
`1−(1−f)³` line (no read-timeout inflation — in-process has no netem; the Docker cross-check sat
slightly above it from load timeouts, caveat 2). **This is the examiner-facing result: the
replicated DNS store's integrity defence is materially weaker than the thesis's majority-vote
analysis claims.**

**Mitigation (for the write-up, not implemented here — `node/storage.py` is Phase-2 code):** require
a real **quorum of ⌈(s+1)/2⌉ *agreeing* responses** before accepting a DHT value — treat a
missing/`None` replica as a *non-vote that still counts against quorum*, and **fall back to iterative
resolution (and store-back) when quorum is not met**, rather than accepting a lone responder. That
restores the `3f²−2f³` behaviour the thesis assumes.

Two placement blocks:
- **random** — f ∈ {0,10,20,30,40,50}% → n_mal = round(f·32) = {0,3,6,10,13,16} chosen uniformly
  from indices 1..31 (node 0, the seed/entry anchor, stays honest), **resampled per run**. Expected
  to track the bound. **f=0 is the honest control.**
- **targeted** — the minimum capturing budget (2 nodes) co-located on **one popular chunk's replica
  set**, so that chunk is forged regardless of the global f. The colluding case that **crosses** the
  bound.

## Metric
**Forged-acceptance (query-weighted)** = replies whose resolved IP is the forged `6.6.6.6`
(`node/malicious.py::FORGED_IP`) ÷ all **successful** replies. In the in-process primary this is read
directly from `resolve_query`'s return value at node 0; in the Docker cross-check it is the
`answer_ip == 6.6.6.6` fraction from `query_gen.py --check-answers`. Also reported:
**forged-acceptance (distinct-chunk)** (fraction of distinct answered domains forged — cache lock-in
makes a chunk consistently forged or not, so this ≈ the structural capture over queried chunks), and
**DNS success rate** (should stay flat — see caveat 1).

Overlaid bounds (both drawn on the figure):
- **intended majority bound** — `P(Binom(s,f) ≥ ⌈(s+1)/2⌉) = 3f² − 2f³` at s=3 (the thesis's
  assumed guarantee — needs >s/2 replicas lying);
- **achieved single-replica bound** — `1 − (1−f)ˢ` (the bound the implementation actually exhibits —
  ≥1 malicious replica suffices, per the headline finding above);
- **structural (realized)** — fraction of the **1000 served chunks** whose replica set actually holds
  ≥2 (majority) and ≥1 (single) malicious under *this run's* seeded placement, from
  `experiments/b1_placement.py::structural_capture_fraction` (the realized bounds this run matches;
  the analytic forms are their large-population limits).

## Results (measured 2026-10-19, seed 20260919)
**Primary = the real in-process ring** (`experiments/b1_inproc.py` → [`B1_tampering.csv`](B1_tampering.csv),
plotted by `experiments/plot_b1.py` → [`fig_B1_tampering.png`](fig_B1_tampering.png)). Full grid
**f ∈ {0,10,20,30,40,50}% × 5 runs**, targeted **× 3 runs**, 1000-query warm-up + 3000-query measured
Zipf pass per run, queries entering the honest node 0. The original Docker/netem run is retained as a
cross-check in [`B1_tampering_emulation.csv`](B1_tampering_emulation.csv) (f ∈ {0,20,40,50}% × 2) — it
**agrees on forged-acceptance** where the grids overlap, validating the transport swap (see below).

| block | f % (realized) | n_mal | forged-accepted % (sd) | majority bound 3f²−2f³ | single bound 1−(1−f)³ | struct(≥1) | success % |
|---|---|---|---|---|---|---|---|
| random   | 0.0  | 0  | **0.00**         | 0.0  | 0.0  | 0.0  | 100.0 |
| random   | 9.4  | 3  | **24.02** (13.85) | 2.5  | 25.6 | 22.3 | 100.0 |
| random   | 18.8 | 6  | **39.80** (12.80) | 9.2  | 46.4 | 45.1 | 100.0 |
| random   | 31.2 | 10 | **65.67** (13.68) | 23.2 | 67.5 | 69.9 | 100.0 |
| random   | 40.6 | 13 | **77.49** (12.15) | 36.1 | 79.1 | 78.4 | 100.0 |
| random   | 50.0 | 16 | **86.73** (13.67) | 50.0 | 87.5 | 87.0 | 100.0 |
| targeted | 6.2  | 2  | **24.44** (target chunk **100.0**) | 1.1 | 17.6 | 13.3 | — |

**Headline — the measured curve sits on the achieved ≥1-replica bound `1−(1−f)³`, NOT the intended
majority bound `3f²−2f³`.** Forged-acceptance is ~3–4× the majority bound at every f (24.0% vs 2.5% at
f≈9%; 65.7% vs 23.2% at f≈31%; 86.7% vs 50% at f=50%) and matches the realized `struct(≥1)` fraction
within run noise (24.0↔22.3, 39.8↔45.1, 65.7↔69.9, 77.5↔78.4, 86.7↔87.0). So an adversary needs only
**one of a chunk's three replicas**, not two, to forge it — the mechanism in the headline-finding box
(honest replicas abstain with `None` and are skipped by the vote; the fabricated reply blocks the
honest write-back).

**Cross-method agreement (in-process primary ↔ Docker/netem cross-check):** at the overlapping points
forged-acceptance matches within run variance — f≈19%: **39.8%** (inproc) vs **39.5%** (Docker);
f≈41%: **77.5%** vs **84.2%**; f=50%: **86.7%** vs **90.3%**; targeted `google.com`: **100%** both,
overall **24.4%** vs **26.0%**. The integrity result is **transport-independent** (the plurality vote
in `node/storage.py::get_chunk` is byte-identical over either transport) — which is exactly why the
fast, reproducible in-process ring is the faithful primary (the b4_inproc.py convention). The Docker
run's slight excess over the ≥1 bound was read-timeout inflation (caveat 2), absent in-process.

- **Honest control (f=0) = 0.00% forged**, votes resolve to the true value / fallback — the effect is
  the adversary, not `chord.py` fragility or cold-start.
- **Targeted/colluding:** just **2 nodes** (f≈6%) co-located on `google.com`'s replica set forge that
  chunk **100%** of the time; because `google.com` is the most popular Zipf domain it alone drives
  **24%** of all answers forged — far above the 1.1% majority bound for that f. Collusion crosses the
  bound exactly as predicted.
- **Success rate stays 100% across f** (right panel) — a forged answer still resolves, so the harm is
  **integrity, not availability**; the whole effect is the forged-acceptance delta over f=0.

**Examiner-facing takeaway:** the replicated DNS store's integrity defence is **materially weaker than
the thesis's majority-vote analysis claims** — ≥1-of-s rather than ≥⌈(s+1)/2⌉ — because the vote
counts only responders and a Byzantine replica can fabricate records it never stored. The mitigation
(a real agreeing-quorum with fallback on no-quorum) is in the headline-finding box.

## The new driver (no frozen edit — CLAUDE.md §2)
B1 adds **only a driver**; the node-side attack machinery already existed and is byte-identical.

**Primary (in-process, like B3/B4/B6):** `experiments/b1_inproc.py` builds a real in-process ring of
`MaliciousNode` (ids identical to the emulation — `node.tests.util.pk_for == b1_placement._pk_for`),
flips f nodes to `lie`, and runs the **real** `node/query.py::resolve_query` path (real `get_chunk`
plurality vote → real fallback). It imports/reads only; `node/*` and `rpos/rpos.py` are untouched.
`experiments/plot_b1.py` draws the figure from the CSV (matplotlib + stdlib only, no node imports).

The original Docker-testbed driver is retained for the cross-check and adds three additive pieces,
all defaulting off so A1–A7 and `rpos/rpos.py` are unaffected:
1. **`experiments/b1_placement.py`** — host-side, reproducible choice of *which* node indices are
   malicious. Node identities are the exact emulation ones (`node_id_from_pk(_pk_for(i))`); replica
   sets come from `sim/chord_sim.ChordRing` + `sim/query_sim._replica_set` (the same converged
   `owner + succ_list[:s]` rule the node and the other sims use), so placement is bit-for-bit
   reconstructible from (N, s, seed). Also exports `analytic_bound` (intended ≥2/3 majority) +
   `effective_bound` (achieved ≥1 single-replica) + `structural_capture_fraction` (realized, either
   threshold) for the analyzer, and a `--self-test`.
2. **`testbed/gen_nodes_compose.py` `--malicious-indices`** (+ `--malicious-mode`, default `lie`) —
   emits `MALICIOUS_MODE: lie` only on the listed node indices; every other node keeps `--mode`
   (default honest). Empty set ⇒ generated compose byte-identical to pre-B1. Threaded through
   `testbed/run_experiment.sh --malicious-indices` exactly as `--replication` was.
3. **`testbed/query_gen.py` `--check-answers`** — compares each reply's A record to the ground-truth
   `answer_ip` (from the zones MANIFEST) and appends `expected_ip,answer_ip,forged`. Off by default ⇒
   CSV header/rows byte-identical to the A-series.

`node/malicious.py` (`lie`), `node/storage.py` (majority vote), `node/run_ring_node.py`
(`MALICIOUS_MODE` consumption → `MaliciousNode`), `node/chord.py`, and `rpos/rpos.py` are **untouched**.

## Workload (frozen — `PARAMETERS.md`)
`--mode nodes`, **N=32**, **s=3**, measured **10 qps**, **30 s warm-up @ 10 qps**, Zipf α=1.0 over
1000 Tranco domains, netem two-tier 5/50 ms, seed 20260919, δ=2.0 s, PLOT_N=1024, DRG in-degree 2.
Placement resampled per run (seed = SEED+run), node 0 always honest.

**As run (2026-10-19, in-process primary):** full grid **f ∈ {0,10,20,30,40,50}% × 5 runs**, targeted
× **3 runs**, warm 1000 + measured 3000 Zipf queries per run — the whole sweep runs in **~3 s** (no
container bring-up), which is why the in-process ring is the primary and the full grid is cheap.
`--seeds`, `--queries`, `--warm`, `--f-levels`, `--target-runs` select the matrix. The Docker
cross-check (`B1_tampering_emulation.csv`) was collected earlier at f ∈ {0,20,40,50}% × 2 runs, 60 s
@ 10 qps.

## Methodology — in-process primary (cold DHT; flip `lie`; warm then measure)
Per (block, point, run): reset every node's store to **empty** (cold) and clear caches, then flip the
host-side malicious index set (`b1_placement.random_indices`/`targeted_indices`, same ids as the
emulation) to `lie`; run a **warm pass** (1000 Zipf queries from node 0) so each touched domain's
value is locked (forged or true); run a **measured pass** (3000 Zipf queries from node 0) reading
`resolve_query`'s returned IP and counting forged-acceptance (`== 6.6.6.6`), distinct-chunk forgery,
and success. **The cold start is essential and deliberate:** it is what lets a lone liar win the
plurality vote (honest replicas abstain with `None`) and suppress the honest write-back — the exact
≥1-of-s mechanism. (Pre-populating the replicas, as B4's routing run does, would hand the honest
replicas the true value and measure the *wrong* majority bound.) Queries enter the **honest node 0**
(A6's isolation pattern), so any forgery comes purely from the DHT replica vote. The Docker
cross-check used the same logic over sockets with `--ring-nodes 1 --check-answers` and a health gate
relaxed to accept any valid A record when `--malicious-indices` is set.

## Honest caveats (flag, don't hide — CLAUDE.md §2)
1. **The attack harms integrity, not availability.** A forged answer still "succeeds" at the DNS
   level (NOERROR + an A record), so the **success rate stays ~flat** across f (smoke: 100% at every
   point). The attack's effect is entirely the **forged-acceptance delta** over the f=0 control, not
   degraded success. The honest control (f=0 → 0% forged, votes almost all `3/3`) is what separates a
   real vulnerability from `chord.py` fragility — and here it confirms the effect is real.
2. **Read-timeout quorum collapse (Docker cross-check only).** Under netem + load, honest replica
   reads sometimes miss the 2 s `get_chunk` timeout while a `lie` node answers instantly, so the
   responder set shrinks and the fast liar wins slightly more often — which is why the Docker run sat
   a little *above* the ≥1 bound (f=50: 90.3% vs 87.5%). The **in-process primary has no such
   timeouts**, so its curve sits cleanly on the ≥1 bound (f=50: 86.7% vs 87.5%). The inflation
   compounds the abstention mechanism (headline finding) rather than causing it, and its absence
   in-process confirms the ≥1-of-s result is the real, transport-independent signal.
3. **Cache lock-in.** Once a chunk's first DHT read is decided, node 0 caches it for its TTL, so a
   chunk is consistently forged or honest thereafter; the distinct-chunk rate therefore ≈ the
   structural capture fraction, while the query-weighted rate is Zipf-weighted toward popular chunks.
4. **Targeted feasibility is B2, not B1.** The targeted block corrupts nodes that *already* own the
   target chunk, to isolate the vote-crossing effect. The **cost of achieving** such placement — can
   an adversary grind node IDs onto a chosen chunk's replica set? — is **B2 (ID-grinding)**.
5. **PoSpace does not defend B1.** Admission challenges verify *plot possession*, not *answer
   correctness*, so a node with a valid plot can still lie on reads. The **only** defence here is the
   replica vote — which is exactly why B1 measures against its bound (and finds it weak).
6. **Structural bound uses the converged-ring replica model** (identical to the simulator and to
   `node/storage.replica_set`). B1 runs without churn, so the live replica sets match the model;
   replica sets under churn (where they can differ) are A6's domain.
7. **Realized f ≠ nominal f.** round(f·32) makes the realized fraction step (e.g. 30% → 10/32 =
   31.25%); the integer n_mal is authoritative and the bound is evaluated at realized f.
8. **In-process latency is the processing floor, not network latency.** `p50/p95/p99_ms` in
   `B1_tampering.csv` are sub-millisecond — the in-process bus has no netem delay — so they are **not**
   comparable to realistic DNS latency and are not a B1 metric (B1's headline is integrity, and
   success stays 100%). Realistic netem latency for B1-style load is in `B1_tampering_emulation.csv`
   (p50 ≈ 3 ms cache-dominated, p95 ≈ 0.6–0.9 s) and in the A-series. The forged-acceptance result is
   transport-independent, which is the whole point of using the fast in-process ring.

## How to reproduce
```
python3 experiments/b1_placement.py --self-test     # deterministic placement check (no Docker)
# PRIMARY (in-process real ring; needs dnspython — run in the rpos-node image or a venv with it):
docker run --rm -v "$PWD":/repo -w /repo rpos-node:latest \
    python experiments/b1_inproc.py --seeds 5 --warm 1000 --queries 3000   # -> B1_tampering.csv
python3 experiments/plot_b1.py                       # -> fig_B1_tampering.png (needs matplotlib)
# CROSS-CHECK (Docker/netem testbed; slow, optional):
bash experiments/run_b1.sh                           # collect over sockets (Docker Desktop)
python3 experiments/b1_tampering.py                  # analyse the snapshots (writes B1_tampering.csv;
                                                     # redirect/keep as B1_tampering_emulation.csv)
```
The in-process sweep runs in ~3 s and is seed-reproducible. Docker snapshots land under
`results/b1/{random/f<f>/run<r>,targeted/run<r>}/` (git-ignored, seed-regenerable).

## Output schema — `B1_tampering.csv`
One row per (source, block, f point):
`source, block, f_pct, n_mal, realized_f_pct, runs, forged_accepted_pct, forged_accepted_sd,
forged_distinct_pct, bound_majority_pct, bound_single_pct, structural_majority_pct,
structural_single_pct, success_rate_pct, success_sd, p50_ms, p95_ms, p99_ms, target,
target_forged_pct, note`. `source` = `inproc` (primary) or, in `B1_tampering_emulation.csv`,
`emulation` (Docker/netem cross-check). `bound_majority_pct` = intended `3f²−2f³`; `bound_single_pct`
= achieved `1−(1−f)³`; `structural_*` = realized fractions over the 1000 chunks for this run's
placement (≥2 and ≥1 malicious). Metrics are the **mean across the runs** (forged-acceptance over
**successful** replies); `*_sd` are the run-to-run standard deviations (the plot's error bars).
`p50/p95/p99_ms` for `source=inproc` are the sub-ms processing floor (caveat 8), not network latency.
`target`/`target_forged_pct` are populated for the targeted block.
