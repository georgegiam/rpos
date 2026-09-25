# A6 — Churn: lookup success vs session length: methodology notes (issue #37, Phase 6, points (ii)/(iii))

Reproducible trail for the A6 experiment. Numbers live in
[`A6_churn.csv`](A6_churn.csv) and [`fig_A6_churn.png`](fig_A6_churn.png); this file records *how*
they were produced and the honest caveats (CLAUDE.md §2 "measure, don't assert" / "flag, don't hide").

## What A6 measures
The **availability** of the resolver under membership churn — the *benefit* side of replication that
A4 (replication cost) deferred here ("its availability benefit shows only under failure → A6/churn").
At the frozen **N=32** emulation ceiling (`PARAMETERS.md` §1), **s=3**, and an unsaturated **10 qps**,
we sweep the **mean node session length** over **{30, 60, 120, 300, ∞} s** (∞ = no-churn control),
3 runs each, over a **120 s** measured window (issue #37), and record per session length: **raw-DHT
lookup success (headline)**, end-to-end client success (secondary), and **p95** (issue #37) / p50 / p99
latency. The deliverable is a **curve of success rate vs session length** (issue #37's done-when).

This is the emulation *headline*; the large-scale churn curve (N=100/1k/10k) lives in
[`../sim/results/churn_sim_curve.csv`](../sim/results/churn_sim_curve.csv) (Phase 5 #28), and A6
re-runs `sim/churn_sim.py` at **N=32** for a direct cross-check (`source=sim` rows).

## Results (measured 2026-09-25, seed 20260919, 3 runs per session length)
Full stats + run-to-run sd in [`A6_churn.csv`](A6_churn.csv).

| mean session (s) | raw-DHT success % (sd) | end-to-end success % | p95 (ms) | mean live pop | source |
|---|---|---|---|---|---|
| 30 | 70.7 (0.30) | 97.4 | 1693 | 27.8 | emulation |
| 60 | 72.7 (1.05) | 96.4 | 1077 | 29.4 | emulation |
| 120 | 72.9 (0.37) | 98.3 | 792 | 30.2 | emulation |
| 300 | 74.8 (0.32) | 99.4 | 821 | 31.3 | emulation |
| ∞ (no churn) | 76.3 (0.12) | 99.8 | 929 | 32.0 | emulation |
| 30 | 96.9 | — | — | 31.8 | sim |
| 60 | 100.0 | — | — | 32.1 | sim |
| 120 | 100.0 | — | — | 31.3 | sim |
| 300 | 100.0 | — | — | 33.7 | sim |
| ∞ | 100.0 | — | — | 32.0 | sim |

**Headline.**
- **Raw-DHT success falls monotonically as sessions shorten** — 76.3 → 74.8 → 72.9 → 72.7 → 70.7 %
  (∞ → 30 s), a clean ~5.6 pp decline (run-to-run sd ≤1.1 pp). The ∞ anchor (76.3 %) reproduces A1's
  steady-state N=32 outcome split (~68 % cache+dht), so the ~24 % baseline "miss" is **cold-start**,
  not churn; the **churn effect is the drop below that anchor**. Even at the most aggressive 30 s
  churn (≈1 departure/s on 32 nodes) the ring + s=3 replication + fallback-on-read keep **>70 %** of
  lookups on the DHT.
- **End-to-end (user-observed) success stays ≥96 %** at every churn level (99.8 % at ∞ → 97.4 % at
  30 s) — the DNS-hierarchy fallback re-fetches whatever churn evicts, so the *user* barely sees the
  loss the raw-DHT view exposes. This is exactly why raw-DHT is the headline (§Metric).
- **The mean live population tracks the injector model** — 27.8 / 29.4 / 30.2 / 31.3 / 32.0 at
  30/60/120/300/∞ s vs the predicted 31·downtime/(session+downtime)+1 (≈27.6 live at 30 s) — a
  built-in check that the churn actually happened at the intended rate.
- **Latency: p50 is cache-dominated and flat** (1.6–2.9 ms median — node 0 caches popular Zipf
  domains); the churn cost shows in the **tail**: p95 nearly doubles under heavy 30 s churn
  (929 → 1693 ms) from stale-routing retries. The ≥60 s points sit in a ~790–1080 ms band with no
  clean monotone trend — the A2 survivorship effect (slow tail queries that time out drop out of
  p95-**of-successful**), so **success rate, not latency-of-successful, is the churn headline**.
- **Sim vs emulation** — `churn_sim` (data-availability model, active 1 s repair, no cold-start) sits
  at 96.9 % (30 s) → 100 % (≥60 s): more optimistic than emulation because it *repairs* replicas every
  round and has no first-query cold-start. The emulation (no re-replication, cold-start included) is
  the pessimistic real-system view. Both agree the **data-loss at N=32/s=3 is modest for sessions
  ≥60 s** — a directional match (caveat 1), not a fitted one.

**Examiner-facing takeaway:** replication (s=3) plus the DNS-hierarchy fallback keep the resolver
**available under churn** — raw DHT lookups degrade only gently (76→71 %) even at ~1 departure/s, and
the user-observed answer rate stays ≥96 %; the visible cost of heavy churn is tail **latency** (p95
≈2×), not correctness. This is the availability *benefit* of replication that A4's cost measurement
deferred here — quantified against both the live testbed and the large-scale simulator.

## The new mechanism — a churn injector (no frozen edit)
The testbed has **no graceful leave** (`node/chord.py` has no `leave()`); the realistic departure is
an ungraceful crash, detected by `node/socket_net.is_up()` (3 consecutive-failure threshold, 3 s
dead_ttl) and healed by `stabilize`. A6 adds, entirely in **new** files (CLAUDE.md §2):
- **`experiments/a6_churn_injector.py`** — a host-side driver that `docker kill` / `docker start`s the
  ring containers on a **seeded per-node alternating-renewal** schedule (each churnable node UP ~
  `Exp(mean_session)`, DOWN ~ `Exp(downtime)`; the emulation analogue of `churn_sim`'s M/M/∞). A
  killed node rejoins with the **same identity** (`NODE_INDEX` is fixed in the compose env → the same
  deterministic pk / ring-id and the same static IP), holding no chunks until re-populated. Every
  kill/start is logged to `churn_events.csv` (`sim_time_s,event,node,live_pop`).
- **Node 0 is never churned** — it is the seed/bootstrap every rejoin depends on, and (see below)
  every measured query enters the ring through it.

It manipulates only containers the compose file already created; `node/*`, `rpos/rpos.py`,
`testbed/query_gen.py`, `testbed/run_experiment.sh` internals, and `sim/churn_sim.py` stay
**byte-identical**.

## Metric — raw-DHT success is the headline (client↔node join)
The emulation logs two files nothing joins at capture time — the client `client.csv`
(`timestamp,domain,resolver_used,latency_ms,success`) and each node's `queries.csv`
(`timestamp,domain,hops,outcome,vote_result`). We pair them per **domain** in time order (the A1
join, pooled by domain because every query enters at node 0 but the *outcome* is logged by whichever
node served the chunk). A lookup is **raw-DHT available** iff its outcome is `cache_hit` or `dht_hit`
(served without the DNS-hierarchy fallback); a `fallback` = a DHT miss. **Raw-DHT success is the
headline** because it is comparable to `sim/churn_sim.py`'s raw-DHT metric and is the only view that
shows a churn curve — end-to-end client success stays ~100 % since the resolver fallback re-fetches
lost chunks (reported as the secondary column, not folded in — the same rule as #28).

## Workload (frozen — `PARAMETERS.md`)
`--mode nodes`, **N=32**, **s=3** (default REPLICATION / SUCC_LIST_LEN → identical to A1/A3/A4's
anchor), **10 qps** measured for **120 s**, **30 s warm-up @ 10 qps** (converge + populate the DHT),
netem two-tier 5/50 ms, seed 20260919, δ=2.0 s, PLOT_N=1024, DRG in-degree 2, Zipf α=1.0 / 1000
Tranco domains. **3 runs** per session length. Injector downtime mean = **5 s** (rejoin gap).
**All measured queries enter at node 0** (`query_gen --ring-nodes 1`).

## Methodology — A4's bring-up (warm @ 10 qps, ring left UP) + background churn
Per (session, run): `run_experiment.sh --mode nodes … --keep-up` does the whole bring-up (zones,
`gen_nodes_compose`, health-gate, netem, 30 s warm-up) and leaves the ring live; we truncate each
node's `queries.csv` to scope logs to the measured window; launch the churn injector in the background
over the 120 s window (skipped for ∞); drive the measured 10 qps load through node 0; snapshot
`client.csv` + each node's `queries.csv` + `churn_events.csv` **while the ring is up**; tear down.
Repeated 3× for error bars.

## Honest caveats (flag, don't hide — CLAUDE.md §2)
1. **No active chunk re-replication in emulation.** `node/*` has no repair loop — a departed node's
   chunks are **not** restored to s=3 copies; the only recovery is the query **fallback**
   re-fetching-and-storing a chunk on read (so popular Zipf chunks self-heal, unpopular ones do not).
   `sim/churn_sim.py` instead restores the full replica set every 1 s. So the emulation raw-DHT curve
   is a **different, more pessimistic** model than the sim — the sim is a **directional cross-check,
   not a fitted match** (as in A5). At N=32 the sim curve is mild (≈97 % at 30 s, 100 % at ≥60 s, a
   finite-ring effect); the emulation is expected to sit **below** it, especially at short sessions.
2. **Routing-collapse vs data-loss.** At 30 s (and possibly 60 s) sessions, ~1 departure/s on a
   32-node ring perturbs `stabilize` (the documented N=64 wall, Phase 3): some misses are the ring not
   re-converging, not the chunk being unavailable. We distinguish them via the node-side outcomes and
   the injector's `live_pop`, and — per plan — let `sim/churn_sim.py` carry the clean large-N curve if
   the emulation degrades. Reported, not hidden.
3. **Ungraceful (crash) departure only** — there is no graceful `leave()`; matches `churn_sim`'s
   replica-departure model and the `is_up`/stabilize recovery path.
4. **Queries enter at node 0** (`--ring-nodes 1`) to **isolate availability**: a query must not fail
   merely because the specific node it was sent to happens to be dead. Node 0 (never churned) does the
   Chord routing, so a miss reflects chunk/route unavailability on the ring. At 10 qps concentrating
   the load on node 0 is negligible.
5. **∞ = no-churn control anchors the cold-start baseline, not 100 %.** Its raw-DHT rate (~70 %)
   matches A1's steady-state N=32 outcome split (~22 % cache + ~47 % dht ≈ 69 %, ~32 % fallback):
   over a short window many of the 1000 Zipf domains are queried for the *first* time and miss the DHT
   (then the fallback stores them back), so a baseline ~30 % fallback is **cold-start, not churn**. The
   churn signal is therefore the **drop in raw-DHT below the ∞ anchor** as sessions shorten, not the
   absolute rate. End-to-end success at ∞ is ~100 % (fallback recovers every cold miss) — that is the
   "harness adds no loss" sanity check. p95 sits in the sub-second-to-~1.5 s band (A1's N=32 range).
6. **`churn_sim` has no latency model** — its rows carry success only (p50/p95/p99 blank); latency is
   the emulation's alone.

## How to reproduce
```
bash experiments/run_a6.sh              # collect: sessions {30,60,120,300,inf} x 3 runs, N=32 (Docker Desktop)
python3 experiments/a6_churn.py         # analyse -> A6_churn.csv + fig_A6_churn.png
```
Snapshots land under `results/a6/s<L>/run<r>/{client.csv, ring/<j>_queries.csv, churn_events.csv}`
(git-ignored, seed-regenerable). Quick sim-only cross-check (no Docker):
`python3 experiments/a6_churn.py --sim-only`. Smoke subset:
`A6_SESSIONS="300 inf" A6_RUNS=1 bash experiments/run_a6.sh`.

## Output schema — `A6_churn.csv`
One row per (source, session length):
`source, n, mean_session_s, qps, duration_s, runs, raw_dht_success_pct, raw_dht_success_sd,
e2e_success_pct, e2e_success_sd, p50_ms, p95_ms, p99_ms, p95_sd, fallback_pct, mean_live_pop, note`.
Emulation percentiles/success are the **mean across the 3 runs**; `*_sd` are run-to-run standard
deviations. `mean_session_s` is `inf` for the no-churn control. The sim rows carry `raw_dht_success`
(= `churn_sim` success_rate) and `mean_live_pop` only; latency and end-to-end columns are blank.
