# B4 — Routing / eclipse: methodology notes (issue #45, Phase 7, examiner point (ii))

Reproducible trail for the B4 attack experiment. Numbers live in
[`B4_eclipse.csv`](B4_eclipse.csv) and [`fig_B4_eclipse.png`](fig_B4_eclipse.png); this file records
*how* they are produced and the honest caveats (CLAUDE.md §2 "measure, don't assert" / "flag, don't
hide").

## What B4 measures
A fraction **f** of the **N=32** ring runs **malicious** with `MALICIOUS_MODE=misroute`
([`node/malicious.py`](../node/malicious.py) `_h_find_successor` / `_h_closest_preceding`): the node
claims to be the successor of **every** key and, asked for the closest preceding node, hands the
querier **back to itself**, so an iterative Chord lookup that reaches it `nxt == n` early-exits at the
**wrong successor**. B4 measures how often a lookup is **eclipsed** (misrouted off the DHT onto the
fallback) and the **extra hops** that costs, swept over f, with a strict **f=0 honest control**.

Crucially, `get_successor` is **not** overridden, so a misrouter still resolves a key lying in its own
successor interval — the attack bites only when the walk must forward **past** the misrouter. And the
lookup feeds `node/storage.py::replica_set` (primary + its successor list), so a wrong primary **near**
the true owner shares successors with the true replica set and the **s=3 read still finds the chunk**.

Two placement blocks (mirroring B1/B3):
- **random** — f ∈ {0,10,20,30,40,50}% → n_mal = round(f·32) = {0,3,6,10,13,16} misrouters chosen
  uniformly from indices 1..31 (node 0, the honest entry anchor, never misroutes), resampled per seed.
  **f=0 is the honest control.**
- **targeted** — isolate a **victim**: one misrouter on the victim's on-path hop. *node* variant =
  eclipse a victim NODE's entire key range; *chunk* variant = eclipse one popular domain.

### Headline finding — replication + fallback blunt RANDOM misroute, but ONE misrouter isolates a chosen victim
Misroute poisons **routing** heavily — up to **61%** of lookups are sent to the wrong owner at f=50%
(finger-table *centrality amplification*: a few of node 0's fingers carry most lookups, so eclipse
sits **above** f at low f) — **but the actual DHT harm is far smaller**: the s=3 replica read over the
wrong primary's successor list usually overlaps the true replica set, so **replication rescues routing
eclipse** (the routing mirror of B3's majority-vote rescue of censorship). Measured raw-DHT lookup
success stays **≥89% through f=50%** and **end-to-end success is 100%** at every f (the honest entry's
iterative-resolution fallback recovers every eclipsed chunk — harm is **extra hops/latency, not
denial**). The honest control (f=0 → 0% eclipse, 100% raw-DHT) proves the effect is the adversary, not
`chord.py` fragility. **Yet the targeted attack is devastating and cheap: a *single* misrouter on one
on-path hop denies a chosen victim node's *entire* 147-chunk range (raw-DHT → 0%, e2e 100% via
fallback).** This is the mirror-and-contrast of B3: censorship needs **all s** replicas to deny one
chunk; eclipse needs **one** misrouter to isolate a whole node — routing attacks are far cheaper than
storage attacks (and B2 showed that one position costs ≈O(N)≈54 hashes to grind).

## Metric
- **raw-DHT lookup success (headline)** = `dht_hit / (dht_hit + fallback)` over node 0's returned
  outcomes (cache excluded; B3/A6 definition). **Eclipse rate = 1 − raw-DHT success** = the
  fallback-forced fraction. Both measured over a Zipf(α=1.0) workload (what clients actually see).
- **extra hops** = `mean(hops | eclipsed/fallback) − mean(hops | honest f=0 DHT)`. An eclipsed lookup
  early-terminates (fewer routing hops) then pays the fallback penalty (+3 iterative steps), so the
  net is **+1.6–2.0 hops** vs the honest control (`extra_hops_delta_vs_f0`).
- **end-to-end success (secondary)** = client-level resolution; stays **100%** (fallback recovers).
- **targeted** = the victim's raw-DHT success (→0, fully eclipsed) and e2e (→100, via fallback).

Overlaid on the figure (decomposition, panel 2):
- **routing-eclipsed** — lookups misrouted to the wrong owner (over all 1000 served chunks);
- **DHT-denied (structural)** — the wrong primary's s-replica read finds nothing (the real per-chunk
  harm; the gap below routing-eclipsed is **replication's rescue**);
- **measured eclipse (Zipf)** — lower still, because popular chunks have short paths and are rescued
  most;
- **i.i.d. reference** `1 − (1−f)^L̄` (L̄ = honest mean hops = 2.54) — a loose upper reference.

## Results (measured 2026-10-16, seed 20260919, 3 seeds/point, 2000 queries/point, N=32, s=3)
Produced by `experiments/b4_inproc.py` → [`B4_eclipse.csv`](B4_eclipse.csv) + [`fig_B4_eclipse.png`](fig_B4_eclipse.png).

| block | f % (realized) | n_mal | raw-DHT success % (sd) | eclipse % | routing-ecl % | DHT-denied % | e2e % | extra hops Δ |
|---|---|---|---|---|---|---|---|---|
| random | 0 (0.0) | 0 | 100.0 (0.0) | 0.00 | 0.0 | 0.0 | 100.0 | — (honest control) |
| random | 10 (9.4) | 3 | 97.1 (3.8) | 2.88 | 21.0 | 12.1 | 100.0 | +2.02 |
| random | 20 (18.8) | 6 | 96.2 (3.8) | 3.77 | 30.9 | 14.8 | 100.0 | +1.69 |
| random | 30 (31.2) | 10 | 93.0 (6.2) | 7.02 | 45.8 | 26.9 | 100.0 | +1.66 |
| random | 40 (40.6) | 13 | 90.6 (6.2) | 9.42 | 54.8 | 36.2 | 100.0 | +1.56 |
| random | 50 (50.0) | 16 | 89.0 (5.0) | 11.00 | 61.3 | 44.1 | 100.0 | +1.78 |
| targeted_node | 3.1 | 1 | **0.0** (victim range) | — | 100 | 100 | **100.0** | — |
| targeted_chunk | 3.1 | 1 | **0.0** (facebook.com) | — | 100 | 100 | **100.0** | — |

- **Random misroute is weak on availability, strong on wasted routing.** Routing is eclipsed up to
  61% at f=50%, but raw-DHT success only falls to 89% (eclipse 11%) and e2e never drops below 100% —
  replication's successor overlap + fallback absorb the attack. The cost is **+~2 extra hops** on an
  eclipsed lookup (one fallback round to the zone).
- **Targeted is the real threat.** One misrouter (idx 8) on victim node #20's single on-path hop
  denies **all 147** of its chunks' DHT path (raw-DHT 0%), and one misrouter (idx 9) denies a chosen
  popular domain (facebook.com) — both still resolve e2e 100% via fallback. Not every popular chunk is
  single-misrouter-deniable (short-path chunks are rescued by replication — `b4_placement.py`'s
  self-test shows e.g. google.com routing-eclipsed 100% but DHT-denied 0%); the attacker picks one
  that is.
- **Honest control (f=0 → 0% eclipse, 100% raw-DHT/e2e)** separates the attack from `chord.py`
  fragility: the effect is entirely the adversary.

## Method — real in-process ring is the PRIMARY (a methodological upgrade over B3)
Unlike B3's `drop` (which black-holes RPCs and **stalls** the in-process transport on 2 s timeouts,
forcing B3 to isolate the storage read), `misroute` replies **fast** and the walk `nxt == n`
early-exits, so the **real** end-to-end `resolve_query` path runs cleanly in-process. So B4's primary
measures real hops and real outcomes from the live node code — more faithful than B3's reconstruction.
`experiments/b4_inproc.py`:
1. build + converge + **populate** the DHT with an **all-honest** ring (node ids identical to the
   emulation — `node.tests.util.pk_for == b1_placement._pk_for`), and snapshot each node's store;
2. for each point, **restore** the pristine store + clear caches, flip f nodes to `misroute`
   **after convergence**, and run the real `resolve_query` from honest node 0 over a Zipf sample;
3. headline = raw-DHT success (eclipse = complement); e2e from the same returns.

**Real ring is authoritative for the bounds too.** Routing depends on finger tables, which converge to
— but are not bit-identical to — the ideal fingers the host-side analytic model builds; on short
lookups that gap can flip an eclipse decision. So the structural lines (routing-eclipsed, DHT-denied)
and the targeted attacker selection are computed by **replaying the live ring's own routing state**
(`real_walk` / `real_path` against `nodes[i].successor()`/`closest_preceding`, with misroute's only
live primitive — `closest_preceding → self` — modelled exactly, and DHT-denial checked against the
real stores). The analytic model (`experiments/b4_placement.py`) remains the **host-side reference**
for the optional socket run and the i.i.d. bound curve.

## The new driver (no frozen edit — CLAUDE.md §2)
- `experiments/b4_placement.py` — host-side placement brain. Reuses B1's `random_indices`,
  `index_to_id_map`, `load_served_domains`; ports the lookup walk (`misroute_walk`), the DHT-denial
  test (`dht_denied` via replica-set overlap), the structural fractions, and the targeted victim
  selection (`victim_eclipse_indices`). `--self-test` is deterministic, no Docker.
- `experiments/b4_inproc.py` — the primary in-process run (above) → `results/B4_eclipse.csv`.
- `experiments/plot_b4.py` — standalone figure (matplotlib + stdlib only) → `fig_B4_eclipse.png`.
- `experiments/run_b4.sh` + `experiments/b4_eclipse.py` — **optional** socket-testbed cross-check →
  `results/B4_eclipse_socket.csv` + `fig_B4_eclipse_socket.png` (a separate file; never clobbers the
  primary).
- **Untouched / byte-identical:** `node/malicious.py` (misroute already exists), `node/chord.py`,
  `node/storage.py`, `node/query.py`, `rpos/rpos.py`, and `testbed/*` (reuses the B1/B3
  `--malicious-indices` / `--malicious-mode` plumbing).

## Workload (frozen — `PARAMETERS.md`)
N=32, s=3, measured Zipf α=1.0 over 1000 Tranco domains, seed 20260919, δ=2 s, PLOT_N=1024, DRG δ=2.
In-process primary: 2000 queries/point × 3 seeds, cold path (IterativeResolver ttl=0 → every query
exercises routing). Optional socket anchor: netem 5/50 ms two-tier, `UPSTREAM_TTL=0`, `--ring-nodes 1`
honest entry.

## Honest caveats (flag, don't hide — CLAUDE.md §2)
1. **Single-origin scope.** Eclipse is measured from the honest entry node 0 (the testbed's
   `--ring-nodes 1` query funnel). From multiple origins an attacker would need to corrupt each
   origin's path to the victim. Stated openly; matches the testbed's entry model.
2. **Flip-after-convergence.** Misrouters are activated only *after* the ring converges. Misroute
   *during* join/stabilize/fix_fingers would additionally poison finger tables and conflate the
   read-path attack with `chord.py` convergence fragility — a **distinct, un-measured attack**
   (join/maintenance-time misrouting) left to future work. This isolates steady-state read-path
   routing poisoning, per the epic's honest-control rule.
3. **Routing-eclipse ≠ DHT-denial.** The headline is the real harm (DHT-denied / fallback-forced).
   Routing-eclipsed is much higher (up to 61%) but mostly rescued by replication; both are reported so
   the gap (replication's value) is visible, not hidden.
4. **Realized f ≠ nominal f** — `round(f·32)` gives realized f = {0, 9.4, 18.8, 31.2, 40.6, 50}%.
5. **Zipf vs uniform.** The measured eclipse (Zipf) is below the uniform per-chunk DHT-denied line
   because popular chunks have short paths and are rescued most — the realistic client-seen harm.
6. **Socket cross-check is optional/flagged.** The in-process run is the most faithful vehicle here;
   the socket anchor adds realistic-network latency only and may be perturbed by `chord.py`
   maintenance under adversarial load (N=64 residual wall, Phase 3). Default anchor is light (f={0,10},
   1 run) and written to a separate CSV.

## How to reproduce
```bash
# 1. placement self-test (no Docker, deterministic)
python3 experiments/b4_placement.py --self-test

# 2. PRIMARY: in-process real-ring run -> results/B4_eclipse.csv  (needs dnspython; use the image)
docker run --rm -v "$PWD":/repo -w /repo rpos-node:latest \
    python experiments/b4_inproc.py --queries 2000 --seeds 3

# 3. figure (matplotlib) -> results/fig_B4_eclipse.png
python3 experiments/plot_b4.py

# 4. OPTIONAL socket cross-check (Docker ring; flaky/slow) -> results/B4_eclipse_socket.csv
B4_F="0 10" B4_RUNS=1 bash experiments/run_b4.sh && python3 experiments/b4_eclipse.py
```
`results/B4_eclipse.csv`, `fig_B4_eclipse.png`, and this file are committed; the per-run snapshots
under `results/b4/` are git-ignored (seed-reproducible, CLAUDE.md §2).

## Output schema — `B4_eclipse.csv`
`source` (inproc) · `block` (random / targeted_node / targeted_chunk) · `f_pct` · `n_mal` ·
`realized_f_pct` · `runs` · `raw_dht_success_pct`(+`_sd`) · `eclipse_rate_pct`(+`_sd`) ·
`e2e_success_pct`(+`_sd`) · `bound_eclipsed_pct` (i.i.d. 1−(1−f)^L̄) · `routing_eclipsed_pct`
(wrong-owner, over all chunks) · `structural_eclipsed_pct` (DHT-denied, over all chunks) · `dht_pct` ·
`fallback_pct` · `mean_hops` · `mean_hops_honest_dht` (f=0 baseline) · `mean_hops_eclipsed` ·
`extra_hops` (within-point) · `extra_hops_delta_vs_f0` (vs honest control) · `target` ·
`target_eclipse_rate_pct` · `target_raw_dht_success_pct` · `target_e2e_success_pct` · `note`.
