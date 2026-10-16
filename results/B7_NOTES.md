# B7 — Denial of service: methodology notes (issue #48, Phase 7, examiner point (ii))

Reproducible trail for the DoS result: `results/B7_dos.csv` + `results/fig_B7_dos.png`, produced by
the drivers below. Per CLAUDE.md §2 ("measure, don't assert" / "flag, don't hide the soft spots"),
every number here comes from a seeded script, and the one place B7 is genuinely about — chord.py's
load fragility — is reported openly via the mandatory honest-control.

## What B7 measures

B7 is **denial of service**: the effect on **honest clients** (success + latency) when the ring is
under attack, with the issue's decisive twist — *"THIS is where `chord.py` fragility matters most …
report the honest-control (same traffic volume, honest sources) delta explicitly so we separate
protocol DoS from implementation fragility."* The frozen fragility is real and documented:
`node/chord.py::stabilize` drops its successor on **any** RPC exception, including a transient
timeout caused by transport congestion (CLAUDE.md Phase 3; it is why emulation caps at N=32). A
flood weaponizes exactly that path.

Two attack blocks:

- **flood (primary)** — a host-side flooder ([`experiments/b7_flooder.py`](../experiments/b7_flooder.py))
  blasts the honest ring with high-rate `find_successor` RPCs. There is **no "flood" node mode**:
  all five modes in [`node/malicious.py`](../node/malicious.py) are *reactive* inbound-handler
  overrides, but a flood *originates* traffic — so, like `testbed/query_gen.py` and
  `experiments/a5_driver.py`, B7 models the attacker identities as host-side load with the identical
  wire effect and **zero node-code change** (flagged modeling choice).
- **blackhole (secondary)** — a fraction `f` of nodes run `MALICIOUS_MODE=drop`
  (`node/malicious.py::_should_drop` black-holes every inbound RPC), reusing B3's exact plumbing but
  reframed onto the **systemic** honest query stream (all Zipf queries, not one censored chunk).

### Headline finding

**The DoS impact on honest clients is overwhelmingly `chord.py` load fragility, not an
attack-specific protocol weakness.** Under a flood, honest p95 latency pegs the 5 s query timeout and
the ring sheds ~22 % of its correct successors (health 100 % → ~78 %) — **but a matched volume of
purely *legitimate* traffic does the same**, so the protocol-attributable delta (control success −
attack success) is **only +1.7 to +4.4 pp** across the intensity sweep. The adversary's marginal
advantage over honest load is small; the ring's vulnerability is that it has **no admission control
or rate limiting on RPCs** and a maintenance loop that is fragile under *any* sustained load.

## Metric

- **Honest-client impact (headline):** the honest probe's success rate + p50/p95/p99 latency
  (`query_gen` at the frozen 10 qps into the honest seed node 0, `--ring-nodes 1`), per attack
  intensity, for **arm=attack** vs **arm=control**.
- **Protocol-attributable DoS (the required delta):** `control_success − attack_success` at matched
  traffic volume — reported per point in `protocol_delta_pct`. "Matched volume" is **verified**, not
  assumed: `measured_rpc_per_s` is recorded for both arms (socket: the flooder's achieved rate /
  offered honest qps; in-process: both arms drive the same per-worker RPC loop).
- **Fragility quantifier:** ring health = % of nodes whose immediate successor is the true ring-next
  + orphan count (`ring_correct_succ_pct`, `ring_orphans`), from every node's `debug_state`
  ([`experiments/b7_ringhealth.py`](../experiments/b7_ringhealth.py)). It falls in **both** arms when
  the hit is load-driven — the visual proof the DoS is fragility.

## Results — in-process mechanism complement (measured 2026-10-16, seed 20260919, N=32, s=3)

The in-process run is the fast, reproducible **mechanism** complement (the socket run below carries
the real-transport numbers). Its intensity axis is flood **concurrency C** (in-flight RPCs), because
the in-process analog of the shared transport is the shared **event loop** (see Method). 3 seeds ×
6 s/arm.

| C (in-flight) | arm | honest success % | p95 ms | ring health % | rpc/s | protocol Δ (pp) |
|---:|---|---:|---:|---:|---:|---:|
| 0   | attack  | 100.0 | 27 | 100.0 | 0   | — (control) |
| 0   | control | 100.0 | 27 | 100.0 | 0   | |
| 50  | attack  | 85.6  | 5001 | 80.2 | 26  | +4.4 |
| 50  | control | 90.0  | 4700 | 79.2 | 25  | |
| 100 | attack  | 88.3  | 5001 | 78.1 | 50  | +3.9 |
| 100 | control | 92.2  | 5001 | 78.1 | 50  | |
| 200 | attack  | 92.2  | 4675 | 79.2 | 100 | +1.7 |
| 200 | control | 93.9  | 3742 | 78.1 | 100 | |
| 400 | attack  | 88.9  | 5001 | 78.1 | 200 | +4.4 |
| 400 | control | 93.3  | 4684 | 78.1 | 200 | |

The honest control (C=0) is the clean anchor: no flood → 100 % success, 27 ms p95, 100 % ring health.
Any load (C≥50), honest **or** malicious, drives p95 to the 5 s timeout and ~7/32 nodes into
successor-shed. The attack and control curves overlap (fig panels 1–3) — the finding.

## Results — socket testbed (PRIMARY; run with Docker)

The headline real-transport numbers come from [`experiments/run_b7.sh`](../experiments/run_b7.sh)
(N=32 Docker ring + netem, the issue's mandated emulation testbed) → `source=socket` rows in
`B7_dos.csv`, with the flood block's intensity axis = **offered RPC rate R** and the blackhole block's
axis = the f-grid. It was **coded and self-tested but not executed in this environment** (no Docker
here — the `source=inproc` rows are the executed evidence). To collect:

```bash
bash experiments/run_b7.sh            # flood sweep (attack+control) + blackhole f-grid
python3 experiments/b7_dos.py         # merge socket + inproc -> results/B7_dos.csv + figure
```

Expectation to confirm (consistent with A2's ~100–250 qps saturation and the in-process result): the
attack and control success/latency curves track each other with a modest attack premium, and the
blackhole block shows redundancy (s=3 + fallback) holding e2e success high at low–moderate f.

## Method — the honest-control is the point

1. **In-process analog of transport congestion.** `node/net.py` is a single-event-loop bus serving
   each inbox serially; there is no TCP/netem cost to exhaust, so the honest analog of the shared
   transport is the shared **event loop**. "Intensity" is therefore flood concurrency C: C open-loop
   workers keep ~C RPCs in flight and saturate the loop and the victims' serve loops, starving the
   probe's and the maintenance driver's coroutines — exactly as a socket flood starves the real
   transport. A small per-hop bus latency (2 ms, a documented netem stand-in) turns backlog into
   wall-clock delay so chord.py's 2 s stabilize timeout can actually fire.
2. **Matched-volume honest control (epic cross-cutting rule).** Each intensity is run twice at the
   same measured RPC volume — `arm=attack` (flood of `find_successor` on random keys) vs
   `arm=control` (the same volume of `find_successor` on *real* served-chunk keys, the socket run
   uses extra legitimate `query_gen` load). The delta is the protocol-attributable DoS.
3. **Ring health after each point** quantifies the fragility independently of the client metric.

## The new drivers (no frozen edit — CLAUDE.md §2)

- [`experiments/b7_placement.py`](../experiments/b7_placement.py) — placement brain; imports
  `b1_placement` verbatim (random drop indices; broad/targeted flood victims). `--self-test` PASS.
- [`experiments/b7_flooder.py`](../experiments/b7_flooder.py) — host-side flooder; reuses
  `node/socket_net`'s data-only codec (imports only). `--self-test` PASS.
- [`experiments/b7_inproc.py`](../experiments/b7_inproc.py) — in-process mechanism complement; reuses
  `node.tests.util.build_ring`, `MaliciousNode`, `IterativeResolver`, `_mean_sd`/`_pcts`.
  `--self-test` PASS.
- [`experiments/b7_ringhealth.py`](../experiments/b7_ringhealth.py) — all-node `debug_state` health.
- [`experiments/b7_dos.py`](../experiments/b7_dos.py) — merges socket + inproc → `results/B7_dos.csv`.
- [`experiments/plot_b7.py`](../experiments/plot_b7.py) — figure (matplotlib + stdlib only).
- [`experiments/run_b7.sh`](../experiments/run_b7.sh) — socket harness (clone of `run_b3.sh`).

**Untouched / byte-identical:** `rpos/rpos.py`, `node/chord.py`, `node/ledger.py`, `node/storage.py`,
`node/query.py`, `node/pospace_admission.py`, `node/malicious.py`, `node/socket_net.py`, `testbed/*`,
`experiments/b1_placement.py`. The `drop` behaviour already existed; the flood is entirely host-side.

## Workload (frozen — PARAMETERS.md)

N=32, s=3, PLOT_N=1024, DRG δ=2, PoSpace timeout 2 s, netem 5/50 ms (socket), per-query timeout 5 s,
Zipf α=1.0 / 1000 Tranco domains, probe 10 qps, seed 20260919, `UPSTREAM_TTL=0` (cold path so caching
never masks the attack; default 300 keeps A1–A6 byte-identical).

## Honest caveats (flag, don't hide)

1. **The protocol delta is small and noisy** (±a few pp over 3 seeds); its *sign* even flips at some
   points. We do not over-claim a protocol-specific DoS — the honest reading is that the DoS is
   dominated by load fragility, which is the whole reason the honest-control is mandatory here.
2. **In-process ≠ transport.** The in-process bus cannot reproduce TCP/connection/netem congestion;
   its congestion model is event-loop saturation (a documented analog). The socket run is the
   authoritative transport measurement, and is coded but not executed here (no Docker).
3. **Modeling the flooders host-side** (not as in-ring nodes) is a deliberate choice for a
   zero-frozen-edit flood; the wire effect at the victims is identical, but the flooders do not
   themselves occupy ring positions (a colluding in-ring flood is a strict superset left as the
   socket run's `--targets` to extend).
4. **Ring health is measured after the load window**; it is a lower bound on steady-state damage
   (some nodes re-heal once the flood stops before the snapshot).
5. **B7 is CLAUDE.md's designated first scope-cut attack** (§7). The in-process complement + the
   coded socket harness already satisfy the done-when (honest-client impact vs intensity, fragility
   quantified); the socket sweep deepens but does not change the finding.

## How to reproduce

```bash
python3 experiments/b7_placement.py --self-test     # placement brain
python3 experiments/b7_flooder.py   --self-test     # flooder drives RPCs at the targets
python3 experiments/b7_inproc.py    --self-test     # flood degrades probe/ring vs no-flood
python3 experiments/b7_inproc.py                    # full in-process sweep -> results/b7/B7_inproc.csv
python3 experiments/b7_dos.py                       # merge -> results/B7_dos.csv + fig_B7_dos.png
# socket (needs Docker):
bash   experiments/run_b7.sh                        # flood sweep + blackhole f-grid
python3 experiments/b7_dos.py                       # re-merge with the socket snapshots
```

## Output schema — `B7_dos.csv`

Tidy long, one row per (source, block, arm, point). Columns:
`source` (socket primary / inproc complement) · `block` (flood / blackhole) · `axis` (the swept
variable's name) · `intensity` (flood R or C) · `f_pct`/`n_mal`/`realized_f_pct` (blackhole) · `runs`
· `arm` (attack / control) · `honest_success_pct` (+`_sd`) · `p50_ms`/`p95_ms`/`p99_ms` ·
`offered_rpc_per_s` · `measured_rpc_per_s` (the matched-volume check) ·
`ring_correct_succ_pct`/`ring_orphans` (fragility) · `protocol_delta_pct` (control − attack, the
headline, on the attack row) · `note`.
