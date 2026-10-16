# B6 — Malicious ledger proposer: methodology notes (issue #47, Phase 7, examiner point (ii))

Reproducible trail for the B6 attack experiment. The numbers live in [`B6_proposer.csv`](B6_proposer.csv)
and [`fig_B6_proposer.png`](fig_B6_proposer.png); this file records *how* they are produced and the
honest caveats (CLAUDE.md §2 "measure, don't assert" / "flag, don't hide").

## What B6 measures

A malicious node proposes **invalid chunk updates** through Algorithm 3 — the two-phase-commit
chunk ledger ([`node/ledger.py`](../node/ledger.py), frozen). Issue #47 asks for the **bad-update
rejection rate** and the **time-to-eviction** of such a proposer, vs the adversary fraction `f`,
with an honest control.

Reading the frozen commit path settles both: the replica-side handlers validate **nothing** about a
proposal's content, the proposer's identity, or its authorization.

- `_h_precommit` ([node/ledger.py:51-56](../node/ledger.py#L51-L56)) rejects a proposal for the
  **only** reason in the whole protocol — a **lock conflict** (the chunk is already pre-committed to
  a *different* `pid`). It never inspects `value`, `domain`, or `src`.
- `_h_commit` ([node/ledger.py:58-70](../node/ledger.py#L58-L70)) accepts if the lock is this `pid`
  **or `None`** (so a proposer can skip phase 1 and commit directly), then **unconditionally** does
  `store[cid] = value` and appends to the hash chain. A malformed value merely skips expiry tracking
  (`except ValueError: pass`) and is **still committed**. The poisoned entry still passes
  `verify_chain()` — tamper-evidence detects log *mutation*, not bad *input*.
- Eviction ([node/pospace_admission.py:143-156](../node/pospace_admission.py#L143-L156),
  `challenge_peer`/`_evict`) fires **only** on `MAX_FAILS=3` consecutive PoSpace **space-proof**
  failures. There is no path from ledger misbehaviour to `fail_counts`/`_evict`.

### Headline finding — the frozen ledger neither rejects a bad proposal nor evicts the proposer

Both requested metrics are degenerate, and that degeneracy *is* the result (the B1/B2/B5 shape — a
measured missing defense):

- **Rejection rate = 0 % at every `f` (measured, f-independent).** The write path is **weaker than
  B1's read path**: B1 forging needs `≥1-of-s` malicious *replicas* on a read; B6 needs **zero**
  malicious replicas — **one** proposer commits arbitrary values to a majority of `s` **honest**
  replicas for any chosen domain. `f` only scales *coverage*, not per-proposal success, so the
  rejection curve is flat 0 %. A single non-replica proposer forges `google.com` end-to-end (all
  `s=3` replicas poisoned, chain still valid) at cost **1**, corrupting **~13.4 %** of the Zipf
  answer stream.
- **Time-to-eviction = ∞ (never).** A malicious proposer holds a **valid** plot, so it passes every
  PoSpace challenge (`fail_count = 0`) and is never evicted — even after committing a stream of
  forged updates. The **positive control** (a corrupted-plot node) *is* evicted in `MAX_FAILS = 3`
  rounds, so the machinery works; it is simply not wired to ledger abuse.
- **Honest control (f=0, valid updates) is also 0 % rejected** — but that is *correct acceptance*.
  The protocol cannot tell a valid proposal from an invalid one; the delta over the honest baseline
  is **zero**. The attack is invisible to the protocol — the vulnerability, not `chord.py` fragility.

## Metric

- **Bad-update rejection rate** = `rejected / proposals` over distinct Zipf-popular domains, swept
  over `f ∈ {0,10,20,30,40,50} %` → `n_mal ∈ {0,3,6,10,13,16}` at N=32 (B0 threat model).
- **Commit acceptance** = fraction of forged proposals committed, with a per-chunk check that **all
  `s` replicas store the forged value** and `verify_chain()` still holds (random + targeted).
- **Time-to-eviction** = rounds of `challenge_peer` until the proposer is taken offline (`∞` = never),
  against a corrupted-plot positive control.

## Results (measured 2026-10-16, seed 20260919, N=32, s=3, in-process ring)

| metric | result |
|---|---|
| rejection rate vs f (f=0…50 %) | **0 % at every f** (40/40 forged updates committed each point); ideal validating protocol = 100 % for f>0 |
| commit acceptance — random | **100 %**, every chunk's `s=3` replicas poisoned, hash chain valid |
| commit acceptance — targeted `google.com` | **forged 100 %** by one non-replica proposer, chain valid, **~13.4 %** of the Zipf answer stream |
| eviction — ledger abuse | **never** (committed 10 forged updates, passed 7 consecutive challenges, `fail_count=0`) |
| eviction — PoSpace-fail control | **evicted in 3 rounds** (= `MAX_FAILS`) — machinery works |
| control — honest proposer | valid updates accepted (rejection 0 = correct), not evicted → effect is adversary-caused |
| **socket cross-check** (live N=32 ring, [`B6_proposer_socket.csv`](B6_proposer_socket.csv)) | valid **5/5** and forged **5/5** committed, **rejection 0 %** both, ring-wide ledger delta **15 = 5·s** each → honest replicas commit a forged value identically to a valid one over the real wire |

## The new driver (no frozen edit — CLAUDE.md §2)

B6 needs **no new malicious mode**: a "malicious proposer" is defined by the **value** it proposes,
and `propose_update` is identical code for honest and malicious nodes (there is no `propose_update`
override in `node/malicious.py`). A chosen node simply calls `propose_update(domain, FORGED)`.

- [`experiments/b6_proposer.py`](../experiments/b6_proposer.py) — the whole experiment (analyzer +
  `--self-test` + the in-process ring measurement + figure), imports/reads only. Reuses
  [`experiments/b1_placement.py`](../experiments/b1_placement.py) (`build_ring`, `random_indices`,
  `replica_indices`, `load_served_domains`) and [`node/tests/util.py`](../node/tests/util.py)
  (`build_ring`) exactly as B4-inproc does.
- [`experiments/b6_driver.py`](../experiments/b6_driver.py) + [`experiments/run_b6.sh`](../experiments/run_b6.sh)
  — the **optional** Docker socket cross-check: a malicious variant of `a5_driver.py` that sends
  `admin_propose` ([node/run_ring_node.py:233-245](../node/run_ring_node.py#L233-L245), from A5) with
  a *forged* value to a live ring and confirms honest replicas commit it. Writes a **separate** file
  [`B6_proposer_socket.csv`](B6_proposer_socket.csv) (B4 pattern), so a flaky testbed never clobbers
  the primary. Equivalence caveat: `admin_propose` makes an honest node the puppet-proposer, which
  faithfully measures "do honest replicas reject a bad value" since replicas never check proposer
  identity.

**Untouched / byte-identical (CLAUDE.md §2):** `rpos/rpos.py`, `node/chord.py`, `node/storage.py`,
`node/ledger.py`, `node/pospace_admission.py`, `node/net.py`, `node/malicious.py`,
`phase1/pospace_drg.py`, `experiments/b1_placement.py`.

## Workload (frozen — PARAMETERS.md)

N=32, s=3, test plot `PLOT_N=1024`, Zipf α=1.0 over the served Tranco set
([`testbed/dns/zones/MANIFEST.json`](../testbed/dns/zones/MANIFEST.json)), `K=40` distinct bad
updates per f-point, eviction probe on a fast `EV_N=8` ring, seed 20260919. `f→n_mal = round(f·N)`.

## Method — in-process ring (primary, authoritative)

As with B2/B4/B5: the result is a protocol **property** reconstructible from the frozen code + a real
converged ring, and **eviction can only be exercised in-process** (socket `_evict` is a no-op —
`net.nodes` holds only the local node). The in-process ring runs the **real** `propose_update` /
`_h_precommit` / `_h_commit` and the **real** `challenge_peer` / `_evict`, so every number is
measured. An all-honest ring is built, converged, and populated with the **correct** records; the
attack then overwrites them through the ledger and we read each honest replica's `store[cid]` /
`ledger` / `verify_chain()` directly. The store + all ledger state are reset between independent
f-points. Needs dnspython → run under the `rpos-node` image (as B4-inproc does).

## Honest caveats (flag, don't hide — CLAUDE.md §2)

1. **f-independence is the point, not a defect.** The rejection curve is flat 0 % because one
   proposer already suffices; sweeping `f` is for completeness and to show per-proposal success does
   not depend on `f` (unlike B1).
2. **The honest control is degenerate by design.** At f=0 valid updates are accepted (0 rejected =
   correct); at f>0 invalid updates are *also* accepted (0 rejected = the bug). The zero delta is the
   finding — the protocol cannot distinguish the two.
3. **Softer bypass not measured.** The query-fallback `store_chunk`
   ([node/storage.py:53-64](../node/storage.py#L53-L64)) skips the ledger entirely (no 2PC, no chain).
   B6's scope is the ledger write path; the bypass is an even weaker target (issue #16).
4. **The only real rejection is a lock conflict.** B6 drives distinct domains so no contention
   arises; a malicious proposer could instead *hold* locks to grief honest updates — that is a DoS
   flavour (→ B7), not integrity, and is out of B6's scope.
5. **Eviction probe runs on EV_N=8** for speed (the ring size does not change whether ledger abuse
   feeds `fail_counts` — it does not). The positive control reproduces `test_pospace_eviction`.
6. **Test plot `PLOT_N=1024`.** Admission cost is A7's subject; here the plot only needs to be valid
   so the proposer passes challenges. The grind/placement cost of a *chosen* position is B2.
7. **Mitigation for Ch. 6/9 (recommended, not implemented).** Add replica-side proposal validation
   (authorize the proposer as the chunk owner/replica or require signed entries; validate the value;
   for `ttl_refresh`, independently re-resolve and compare to upstream) and wire repeated bad
   proposals into the `MAX_FAILS`/`_evict` consensus-eviction path. B0 lists both as "new code"; per
   the B1/B2/B5 convention B6 measures the frozen system and recommends the fix in prose.

## How to reproduce

```bash
# 1. deterministic self-test (needs the node env for the in-process ring; the image has it)
docker run --rm -v "$PWD":/repo -w /repo rpos-node:latest \
    python experiments/b6_proposer.py --self-test

# 2. PRIMARY: in-process real-ring run -> results/B6_proposer.csv (+ figure if matplotlib present)
docker run --rm -v "$PWD":/repo -w /repo rpos-node:latest \
    python experiments/b6_proposer.py

# 3. OPTIONAL socket cross-check (Docker ring; flaky/slow) -> results/B6_proposer_socket.csv
B6_F="0 10" B6_RUNS=1 bash experiments/run_b6.sh
```

`results/B6_proposer.csv`, `fig_B6_proposer.png`, and this file are committed; per-run socket
snapshots are git-ignored (seed-reproducible, CLAUDE.md §2).

## Output schema — `B6_proposer.csv`

`metric` (rejection_vs_f / commit_acceptance / eviction / control) · `source` (ring_inproc, or
analytic when the node stack is unavailable) · `block` (random / targeted / ledger_abuse /
pospace_fail_control) · `f_pct` · `n_mal` · `realized_f_pct` (`round(f·N)/N`) · `proposals` ·
`committed` · `rejected` · `rejection_rate_pct` · `ideal_rejection_pct` (a validating protocol:
0 at f=0, 100 at f>0) · `chain_valid` · `target` · `target_forged_pct` · `target_share_pct` (Zipf
share of the answer stream the target corrupts) · `evicted` · `time_to_eviction_rounds` (`inf` =
never) · `note`.
