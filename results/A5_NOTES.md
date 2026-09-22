# A5 — Update commit cost: methodology notes (issue #36, Phase 6, examiner point (iii))

Reproducible trail for the A5 experiment. Numbers live in
[`A5_updates.csv`](A5_updates.csv) and [`fig_A5_updates.png`](fig_A5_updates.png); this file
records *how* they were produced and the honest caveats (CLAUDE.md §2 "measure, don't assert" /
"flag, don't hide").

## What A5 measures
The **cost of a coordinated update** — the resolver's *write* path, Algorithm 3's two-phase commit
(`node/ledger.py::propose_update`). At the frozen **N=32** emulation ceiling (`PARAMETERS.md` §1)
and the frozen replication factor **s=3**, we drive **50 real ledger updates** over the live ring
and record, per update: **commit latency**, **messages per update**, and **ledger size growth**
(issue #36's done-when: mean commit latency and message count). 3 runs for run-to-run error bars.

Each update is an Algorithm-3 commit: locate the chunk's replica set (route to the primary + one
`get_succ_list`), **pre-commit** to the s replicas (majority of yes votes), then **commit** to the
s replicas — each appending one entry to its hash-chained log. So a committed update appends **s
entries ring-wide** (one per replica); that is the ledger's growth.

## Results (measured 2026-09-22, seed 20260919, N=32, s=3, 3 runs)
Full stats + run-to-run sd in [`A5_updates.csv`](A5_updates.csv).

| metric | emulation (measured, 3 runs) | simulation (model) |
|---|---|---|
| commit latency p50 (ms) | 583.0 (sd 3.2) | 438.5 |
| commit latency p95 (ms) | 834.4 | 646.5 |
| commit latency p99 (ms) | 866.6 | 826.5 |
| messages per update | 22.08 (wire) | 18.75 (logical) |
| round-trips per update | 11.04 | 9.38 |
| ledger entries per committed update | 3 (= s) | 3 (= s) |
| ring-wide ledger growth | 150 = 50×3, every run | 44 847 over 2 h |
| committed | 50 / 50, every run | — |

**Headline.**
- **Commit latency** is dominated by the two 2PC round-trips over netem (pre-commit to s replicas,
  then commit to s replicas) on top of the Chord locate. Measured emulation **p50 ≈ 583 ms**
  (sd 3.2 ms across 3 runs, p95 834 / p99 867 ms) sits in the same sub-second band as the sim model
  (438 ms). Emulation runs above the model because `propose_update` issues the per-replica calls
  **sequentially** (sum of RTTs) while the sim models each phase as **parallel** fan-out (max RTT),
  and because the emulation ring routes at **+~0.5 hop above theory** (imperfect fingers,
  PARAMETERS.md §2); the sim routes a perfectly-converged ring. This is the strongest statement
  available since the update path has **no calibrated baseline** (caveat 1).
- **Messages per update** is **counted on the wire** in emulation (`socket_net.rpc_counter` around
  the unchanged commit) — **22.08 messages/update** (11.04 round-trips) — vs the sim's 18.75 (9.38
  round-trips). A committed update costs `locate_rt + 2·s` round-trips (locate = route hops +
  `get_succ_list`; then s pre-commit + s commit). Note the emulation count is slightly **above** the
  sim: the extra ~1.7 locate round-trips from emulation's +0.5-hop routing offset outweigh the
  self-RPC saving of the wire count (caveat 2). Storage cost is also ×s (s copies of every record).
- **Ledger growth is exactly `committed × s`** — validated ring-wide end-to-end: the driver sums
  `len(node.ledger)` over all 32 nodes before and after the run (`growth.json`), and the delta
  equals `committed × 3` in every run. Per update the chain grows by s tamper-evident entries
  (`verify_chain` walks `prev`/`hash`); the sim's 2 h horizon (client updates **plus** TTL-expiry
  refreshes) shows the growth-over-time curve a 50-update run cannot.

**Examiner-facing takeaway:** a coordinated, tamper-evident update costs one Chord lookup plus two
majority round-trips to s replicas (≈ 2·(locate+2s) messages), sub-second at the test scale, and
grows the ledger by exactly s entries — the price of consensus + a verifiable audit log on the
write path.

## The new mechanism — driving updates without touching frozen code
There is no DNS UPDATE opcode and `testbed/query_gen.py` is read-only, so updates cannot be driven
the way queries are. A5 adds, entirely in **Phase-3 (non-frozen) code**:
- **`node/run_ring_node.py`** — two inert admin RPCs (the `debug_state` diagnostics pattern):
  `admin_propose(domain, value, action)` runs `node.propose_update` **unchanged**, timing it with
  `perf_counter` and counting its wire RPCs, and `admin_ledger_len()` returns `len(node.ledger)`.
  Both are unreachable unless the driver calls them, so a normal run (and A1–A4) is byte-identical.
- **`node/socket_net.py`** — a `contextvars`-based per-task wire-RPC counter (`rpc_counter`), OFF
  by default. Because an asyncio task carries its own contextvars copy, the counter set inside the
  `admin_propose` handler captures exactly that update's RPCs and is isolated from the concurrent
  maintenance loop (a different task). No-op unless set → A1–A4 unaffected.
- **`experiments/a5_driver.py`** — a bare RPC **client** (a `SocketNetwork` used outbound-only,
  never a ring member; the `query_gen` client-container pattern) that issues the 50 `admin_propose`
  calls to node-0 and reads ring-wide ledger length before/after.

`node/chord.py`, `node/ledger.py`, and `rpos/rpos.py` stay **byte-identical** (CLAUDE.md §2 freeze).

## Workload (frozen — `PARAMETERS.md`)
`--mode nodes`, **N=32**, **s=3** (default REPLICATION / SUCC_LIST_LEN → identical to A1–A3), **50
updates** to 50 distinct domains (seeded shuffle of the served set), 200 ms spacing, **30 s warm-up
at 10 qps** (converge + populate the DHT), netem two-tier 5/50 ms, seed 20260919, δ=2.0 s,
PLOT_N=1024, DRG in-degree 2, ttl 300 s on each written record. **3 runs.** The proposer is node-0.
Zipf is irrelevant here (each update targets a different chunk).

## Methodology — A4's bring-up (warm @ 10 qps, ring left UP)
Each run reuses `run_experiment.sh --mode nodes … --keep-up` for the whole ring lifecycle (zones,
`gen_nodes_compose`, health-gate, netem apply, 30 s warm-up), then drives the 50 updates against
the live ring via the driver container, then tears down. The driver writes `updates.csv` +
`growth.json` directly to the host mount (no while-up snapshot needed — the client holds all the
per-update results itself). Repeated 3× for error bars.

## Message model
Emulation messages/update is a **direct wire count** (not the modeled `ring_round_trips` used for
A3/A4's queries): `socket_net.rpc_counter` increments per outbound RPC method issued by the commit
(`find_successor` hops, `get_succ_list`, `ledger_precommit`×s, `ledger_commit`×s). A round-trip =
req+resp = 2 messages, matching `sim/ledger_sim`'s `messages = 2·round_trips`. The sim value is the
model at the same N/s.

## Honest caveats (flag, don't hide — CLAUDE.md §2)
1. **The update path is NOT calibrated.** `sim/calibrate.py` fits only the read path (#29); there is
   no emulation update-latency baseline. So the emulation numbers are the **measured headline**, and
   the sim is an analytic **model** cross-check (its per-leg delay weights are inherited from
   `query_sim`), not a fitted match. `sim/ledger_sim` also models each 2PC phase as **parallel**
   fan-out (max RTT) while `propose_update` issues the per-replica calls **sequentially** (sum RTT),
   so the sim latency is a lower bound — the same divergence flagged in A4.
2. **Emulation counts WIRE round-trips; the sim counts LOGICAL ones.** Self-directed calls
   short-circuit in `NodeServer.call` before reaching the socket, so when the proposer is itself a
   replica/primary those RPCs are not on the wire and are not counted — pulling the wire count
   *below* the sim's logical `2·round_trips`. At N=32 the proposer (node-0) is rarely the
   primary/a replica of a random chunk, so that saving is small and is **outweighed** by the extra
   locate round-trips from emulation's +0.5-hop routing offset (caveat 1) — so the measured
   messages/update (22.08) lands slightly *above* the sim's 18.75, not below. Both effects are real
   and stated; the wire count is the honest thing that actually crossed the network.
3. **`entries_appended` per update is reported as s (=3);** the *authoritative* growth is the
   ring-wide `admin_ledger_len` delta in `growth.json` (before/after over all 32 nodes), which
   equals `committed × s` in every run — a real end-to-end check that each committed update appended
   one entry on each replica.
4. **Single proposer, no contention.** All 50 updates come from node-0 to distinct domains, so no
   two proposals contend for the same chunk lock and there are no aborts at this scale. The abort
   path (pre-commit lock conflict → s abort RPCs) is exercised by `node/tests/test_ledger.py` and
   `sim/ledger_sim`'s self-test, not by this steady-state workload.

## How to reproduce
```
bash experiments/run_a5.sh              # collect: 50 updates x 3 runs on N=32, s=3 (Docker Desktop)
python3 experiments/a5_updates.py       # analyse -> A5_updates.csv + fig_A5_updates.png
```
Snapshots land under `results/a5/run<r>/{updates.csv, growth.json}` (git-ignored, seed-regenerable).
Quick sim-only cross-check (no Docker): `python3 experiments/a5_updates.py --sim-only`.

## Output schema — `A5_updates.csv`
One row per source (emulation, sim):
`source, n, s, updates_measured, runs, committed_mean, committed_sd, p50_ms, p95_ms, p99_ms,
p50_sd, messages_per_update, messages_per_update_sd, round_trips_per_update,
ledger_entries_appended, note`. Emulation percentiles are the **mean across the 3 runs** over
**committed** updates; `*_sd` are run-to-run standard deviations. `ledger_entries_appended` is the
mean ring-wide `growth.json` delta (emulation) / total entries over the 2 h horizon (sim). The sim
row is a single deterministic run (its `updates_measured` is the client-update count over the
horizon; its latency/messages are over committed client updates).
