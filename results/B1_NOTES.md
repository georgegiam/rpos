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
the intended 2.5 / 9 / 23 / 36 / 50%. The measured curve sits on (slightly above, from read
timeouts under load — see caveat 2) the `1−(1−f)³` line. **This is the examiner-facing result: the
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
**Forged-acceptance (query-weighted)** = client replies with `answer_ip == 6.6.6.6` ÷ all
**successful** replies (NOERROR + A record), from `query_gen.py --check-answers`. Also reported:
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

## Results (measured 2026-10-03, seed 20260919)
Collected by `experiments/run_b1.sh` and analysed by `experiments/b1_tampering.py` →
[`B1_tampering.csv`](B1_tampering.csv) + [`fig_B1_tampering.png`](fig_B1_tampering.png). Random sweep
**f ∈ {0,20,40,50}% × 2 runs**, targeted **× 1 run**, **60 s** measured window @ 10 qps,
`--ring-nodes 1` (honest node-0 entry). (A fuller grid f∈{0,10,20,30,40,50}%×3 at 120 s is a
drop-in re-run — `bash experiments/run_b1.sh` with the defaults — but the trend below is already
unambiguous; see "Workload".)

| block | f % (realized) | n_mal | forged-accepted % (sd) | majority bound 3f²−2f³ | single bound 1−(1−f)³ | struct(≥1) | success % |
|---|---|---|---|---|---|---|---|
| random   | 0.0  | 0  | **0.00**        | 0.0  | 0.0  | 0.0  | 99.8 |
| random   | 18.8 | 6  | **39.53** (13.98) | 9.2  | 46.4 | 37.0 | 99.7 |
| random   | 40.6 | 13 | **84.15** (4.26)  | 36.1 | 79.1 | 79.8 | 99.9 |
| random   | 50.0 | 16 | **90.25** (6.01)  | 50.0 | 87.5 | 87.4 | 100.0 |
| targeted | 6.2  | 2  | **26.04** (target chunk **100.0**) | 1.1 | 17.6 | 13.3 | 99.8 |

**Headline — the measured curve sits on the achieved ≥1-replica bound `1−(1−f)³`, NOT the intended
majority bound `3f²−2f³`.** Forged-acceptance is ~4× the majority bound at every f (39.5% vs 9.2% at
f≈19%; 90.3% vs 50% at f=50%) and matches the realized `struct(≥1)` fraction within run noise
(39.5↔37.0, 84.2↔79.8, 90.3↔87.4). So an adversary needs only **one of a chunk's three replicas**,
not two, to forge it — the mechanism in the headline-finding box (honest replicas abstain with `None`
and are skipped by the vote; the fabricated reply blocks the honest write-back). The small excess
over the realized ≥1 line at high f is read-timeout quorum collapse (caveat 2).

- **Honest control (f=0) = 0.00% forged**, votes almost all `3/3` — the effect is the adversary, not
  `chord.py` fragility or cold-start.
- **Targeted/colluding:** just **2 nodes** (f≈6%) co-located on `google.com`'s replica set forge that
  chunk **100%** of the time; because `google.com` is the most popular Zipf domain it alone drives
  **26%** of all answers forged — far above the 1.1% majority bound for that f. Collusion crosses the
  bound exactly as predicted.
- **Success rate stays ~100% across f** (right panel) — a forged answer still resolves, so the harm is
  **integrity, not availability**; the whole effect is the forged-acceptance delta over f=0.

**Examiner-facing takeaway:** the replicated DNS store's integrity defence is **materially weaker than
the thesis's majority-vote analysis claims** — ≥1-of-s rather than ≥⌈(s+1)/2⌉ — because the vote
counts only responders and a Byzantine replica can fabricate records it never stored. The mitigation
(a real agreeing-quorum with fallback on no-quorum) is in the headline-finding box.

## The new driver (no frozen edit — CLAUDE.md §2)
B1 adds **only a driver**; the node-side attack machinery already existed and is byte-identical.
Three additive pieces, all defaulting off so A1–A7 and `rpos/rpos.py` are unaffected:
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

**As run (2026-10-03):** random sweep **f ∈ {0,20,40,50}%** × **2 runs**, targeted × **1 run**, **60 s**
measured window — a deliberately trimmed matrix (9 bring-ups) because the ≥1-vs-≥2/3 finding is already
unambiguous at these points. The script defaults to the fuller **f ∈ {0,10,20,30,40,50}% × 3 runs,
120 s** (`bash experiments/run_b1.sh`), and the smoke additionally confirmed f=50 at `--ring-nodes 32`;
all give the same headline. Env knobs (`B1_F`, `B1_RUNS`, `B1_DURATION`, `B1_TARGET_RUNS`) select the
matrix.

## Methodology — A4/A6's bring-up (warm @ 10 qps, snapshot ring logs WHILE UP)
Per (block, point, run): compute the malicious index set host-side (`b1_placement.py`, written to
`placement.json`); bring up N=32 with `--malicious-indices` + `--keep-up`; warm @ 10 qps to converge
and populate the DHT (warm-up runs with the malicious nodes **already placed**, so the warm reads are
themselves subject to forgery — consistent); truncate node logs to scope the window; drive the
measured **10 qps** load (60 s as-run; 120 s default) with **`--ring-nodes 1`** (queries enter the **honest seed node 0**
only — A6's isolation pattern, so any forgery comes purely from the DHT replica vote, not from
entry-node behaviour; node 0 still queries all domains under Zipf, so it lands on captured chunks)
and **`--check-answers`**; snapshot `client.csv` + each node's `queries.csv` while the containers
still run; tear down. (The smoke used `--ring-nodes 32`; both give the same headline, node-0-only is
the cleaner isolation and matches A6.) The nodes-mode **health gate** is relaxed to accept any valid
A record (not the honest `answer_ip`) when `--malicious-indices` is set — otherwise the probe chunk's
forged reply would hang the gate; default (no malicious) still requires the honest answer.

## Honest caveats (flag, don't hide — CLAUDE.md §2)
1. **The attack harms integrity, not availability.** A forged answer still "succeeds" at the DNS
   level (NOERROR + an A record), so the **success rate stays ~flat** across f (smoke: 100% at every
   point). The attack's effect is entirely the **forged-acceptance delta** over the f=0 control, not
   degraded success. The honest control (f=0 → 0% forged, votes almost all `3/3`) is what separates a
   real vulnerability from `chord.py` fragility — and here it confirms the effect is real.
2. **Read-timeout quorum collapse inflates the result above even the 1−(1−f)³ line.** Under netem +
   load, honest replica reads (real lookups) sometimes miss the 2 s `get_chunk` timeout while a `lie`
   node answers instantly (fabricated, no work), so the responder set shrinks further and the fast
   liar wins more often. This is why the smoke's f=50 measured 96% vs the 91.4% realized ≥1 structural
   bound. It compounds the abstention mechanism (headline finding) rather than causing it — f=0 shows
   full `3/3` quorum under the same load.
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

## How to reproduce
```
python3 experiments/b1_placement.py --self-test     # deterministic placement check (no Docker)
bash experiments/run_b1.sh                           # collect: random sweep + targeted (Docker Desktop)
python3 experiments/b1_tampering.py                  # analyse -> B1_tampering.csv + fig_B1_tampering.png
```
Smoke subset: `B1_F="0 50" B1_RUNS=1 B1_DURATION=20 bash experiments/run_b1.sh`. Random sweep only:
`B1_TARGETED=0 bash experiments/run_b1.sh`. Snapshots land under
`results/b1/{random/f<f>/run<r>,targeted/run<r>}/{client.csv, placement.json, ring/}` (git-ignored,
seed-regenerable); `B1_tampering.csv` is the committed summary.

## Output schema — `B1_tampering.csv`
One row per (block, f point):
`block, f_pct, n_mal, realized_f_pct, runs, forged_accepted_pct, forged_accepted_sd,
forged_distinct_pct, bound_majority_pct, bound_single_pct, structural_majority_pct,
structural_single_pct, success_rate_pct, success_sd, p50_ms, p95_ms, p99_ms, target,
target_forged_pct, note`. `bound_majority_pct` = intended `3f²−2f³`; `bound_single_pct` = achieved
`1−(1−f)³`; `structural_*` = realized fractions over the 1000 chunks for this run's placement (≥2 and
≥1 malicious). Emulation metrics are the **mean across the 3 runs** (forged-acceptance over
**successful** client rows); `*_sd` are the run-to-run standard deviations (the plot's error bars).
`target`/`target_forged_pct` are populated for the targeted block.
