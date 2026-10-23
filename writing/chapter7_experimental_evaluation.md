<!--
  Chapter 7 — Experimental Evaluation (Phase 9, W1: issue #56)
  Scope of this file: §7.1–§7.5 (testbed, methodology, parameter justification, baseline).
  §7.6–§7.8 (Parts A/B/C results) are reserved stubs, drafted by W2–W4.

  House style for porting into the external LaTeX source:
    * numeric [n] citations; external works are marked [CITE: …] for key reconciliation
    * first-person-plural ("we") voice; British spelling
    * past tense for what was built/run, present tense for analysis
  Every quantitative claim names the results/ CSV (or source file) it comes from.
  This chapter is pure synthesis of Phases 2–8 — it introduces no new measurement.
-->

# Chapter 7 — Experimental Evaluation

## 7.1 Introduction and scope

The evaluation of the proposed resolver in the original submission (former Section 6.5)
rested on analytical projection rather than measurement. Resolution latency was *modelled*
as `L ≈ ½·log₂N · τ` and, assuming `N = 1000` peers and a per-hop delay `τ = 50 ms`,
*projected* at roughly `250 ms`; throughput was asserted to grow linearly with the number of
peers; and the resilience of the design to malicious behaviour was argued only through the
closed-form expressions of the threat model (for example an eclipse probability `f^d`, which
for `f = 0.2` and `d = 10` evaluates to `≈ 1.02 × 10⁻⁷`). No testbed was built, no software
was exercised, and no adversary was ever run against the system. This chapter replaces that
analysis in full with a measured, reproducible evaluation.

The chapter answers the two experimental requirements raised by the examiners directly.
Examiner point **(ii)** calls for experimental or simulation validation of the *complete*
system, including the analysis of malicious scenarios rather than only the happy path.
Examiner point **(iii)** calls for a performance analysis — latency, throughput, and
scalability — of the whole resolver, not merely of Proof-of-Space plot initialisation, which
is all the original thesis measured. We address (iii) in **Part A** (Section 7.6) and (ii) in
**Part B** (Section 7.7); a third strand, **Part C** (Section 7.8), completes the separate
examiner point **(i)** by comparing the proposed Proof of Space against Chia's construction.

Our strategy throughout is **emulation first, simulation for scale**. We built a container-based
testbed in which every resolver node runs the real protocol stack and communicates over real
sockets, forming a genuine Chord [CITE: Stoica-Chord] distributed hash table (DHT) across
containers; this is the system under test for every performance and attack experiment. The
reliable ceiling of the emulation on our hardware is `N = 32` nodes (Section 7.3.3); to reach
the thousand- to ten-thousand-node regime the thesis discusses, we built a discrete-event
simulator that reproduces the same protocol logic and is calibrated against the `N = 8` and
`N = 32` emulation results before it is trusted at scale. The emulation establishes that the
implemented system behaves correctly and measures it at realistic small scale; the calibrated
simulator carries the large-`N` scalability argument.

Every quantitative claim in this chapter is reproducible and traces to a comma-separated-value
(CSV) file or a figure committed under `results/` in the accompanying code repository
(Appendix [CITE: appendix-repo]); the relevant filename is named at each claim. The remainder
of the chapter is organised as follows. Section 7.2 describes the testbed architecture.
Section 7.3 sets out the methodology: reproducibility, the frozen parameter set and its
justification, and the emulation-versus-simulation split. Section 7.4 reports the Unbound
baseline against which the resolver's performance is measured. Section 7.5 is a consolidated
reproducibility statement. Sections 7.6–7.8 then present Parts A, B, and C.

## 7.2 Testbed architecture

### 7.2.1 Overview

The testbed is driven by a single command, `testbed/run_experiment.sh`, which brings up the
containers, waits for them to become healthy, applies network emulation, warms the system,
drives a workload, collects the per-run CSVs, and tears everything down. It exposes two
operating modes, selected by `--mode`:

- **nodes-mode** instantiates the real decentralised resolver: `N` containers, each running
  the complete node stack over TCP sockets, that join into a single Chord ring and answer DNS
  queries from the DHT. This is the *system under test*.
- **host-mode** runs a single Unbound [CITE: unbound] recursive resolver against the *same*
  containerised DNS hierarchy and under the *same* emulated delays. This is the *baseline*
  (Section 7.4).

Because both modes share the DNS world and the network emulation, the comparison between the
proposed resolver and a mature production resolver is like-for-like.

A ground rule of the amendments work constrains the whole testbed: the code that produced the
thesis's original measurements must remain byte-identical so that results stay reproducible and
defensible. In particular the original plotter (`rpos/rpos.py`) and the core Chord
implementation (`node/chord.py`) are frozen. Every capability the testbed needed beyond the
frozen core — the socket transport, the scale and replication controls, the container
orchestration, and the fault- and attack-injection hooks — was added in *new* files, or wired
through environment variables and runtime overrides that leave the frozen sources untouched.
Where this matters to a specific measurement it is noted again below.

### 7.2.2 Containerised DNS hierarchy

Both modes resolve names against a self-contained, authoritative DNS hierarchy built from five
NSD [CITE: nsd] servers on an isolated Docker network (`172.28.0.0/24`), generated by
`testbed/dns/generate_zones.py` from the single source of truth `testbed/dns/topology.json`:

- a **root** server (`dns-root`, `172.28.0.2`);
- two **top-level-domain** servers for `com` (`dns-tld-com`, `172.28.0.3`) and `org`
  (`dns-tld-org`, `172.28.0.4`); and
- two **authoritative** servers, `auth1` (`172.28.0.5`) and `auth2` (`172.28.0.6`), which hold
  the terminal address records.

The hierarchy implements a genuine referral chain: the root delegates `com.` and `org.` with
`NS` records and glue, each TLD delegates every served domain to one of the two authoritative
servers, and only the authoritative servers answer with an `A` record. A resolver must
therefore iterate root → TLD → authoritative exactly as it would on the public Internet.

The zone set is populated with **1000 domains** drawn in rank order from a vendored snapshot of
the Tranco popularity list [CITE: tranco] (`testbed/dns/tranco/`, provenance recorded alongside
it), split evenly between the `com` and `org` TLDs. Each domain is assigned a Time-To-Live
(TTL) drawn deterministically from the ladder `{300, 600, 900, 1800, 3600}` seconds, so that
the workload exercises the full TTL range a production resolver would see. Answer addresses are
deterministic synthetic values inside `10.0.0.0/8`, disjoint from the infrastructure subnet, so
that a correct answer is unambiguous and a forged answer (Part B) is detectable. The generator
emits a ground-truth manifest, `testbed/dns/zones/MANIFEST.json`, mapping each domain to its
expected address, authoritative server, and TTL; the workload generator and the resolver nodes
both consume this manifest, and the entire zone set is regenerated bit-for-bit from the fixed
inputs, so it is omitted from version control.

### 7.2.3 Resolver ring and socket transport

In nodes-mode the ring is described by a Compose file generated per run by
`testbed/gen_nodes_compose.py`. Rather than scaling an anonymous replica, the generator emits
one explicitly named service, `rpos-node-{j}` for `j = 0 … N−1`, so that identity and
addressing are deterministic. The services share a dedicated network (`172.30.0.0/24`) and are
given **static IP addresses** `172.30.0.(10 + j)`, supplied to each container through the
environment variables `RING_IP_PREFIX` and `RING_IP_BASE`. Node 0 is the bootstrap seed; the
remaining nodes join through it after a short, index-proportional delay (`JOIN_STAGGER`,
default `0.4 s`) so that `N` nodes do not all contact the seed in the same instant.

Each container runs `node/run_ring_node.py`, which (i) builds the node's v3 depth-robust-graph
(DRG) Proof-of-Space plot (the construction frozen in Phase 1, imported rather than copied),
(ii) starts the socket server, (iii) binds a **UDP DNS front end** so that the node answers
real DNS `A` queries, and (iv) creates or joins the ring. A maintenance loop then runs every
`1.0 s`: it always runs the cheap ring-cycle protocol (`stabilize` and `check_predecessor`)
first — because the frozen Chord code sheds its successor on any failed maintenance RPC — and
spaces the heavier work out, refreshing the most significant finger-table entries roughly every
`4 s` and issuing a periodic Proof-of-Space challenge roughly every `5 s`. The finger refresh
is a scale fix added outside the frozen code: the original `fix_fingers` advances only one of
160 finger slots per call, which converges too slowly once a large ring untangles its initial
join, so `run_ring_node.py` additionally refreshes the top `≈ log₂N` slots concurrently. These
intervals are listed in Table 7.1.

The transport is `node/socket_net.py`, a drop-in replacement for the in-process message bus
used during initial node development (Phase 2): it exposes the identical interface, so the
Chord, storage, ledger, query, and admission logic run byte-for-byte unchanged on either
transport, and only the delivery mechanism differs. The socket layer is deliberately hardened,
because a malicious node sits on this wire in Part B and the transport itself must not become an
attack surface:

- RPCs are carried over TCP with a **length-prefixed, type-tagged JSON codec** that can
  reconstruct only a fixed set of primitive types; anything else is refused at encode time.
  JSON is used in preference to a binary format because node identifiers are 160-bit integers,
  which JSON preserves exactly.
- A hard **8 MiB frame cap** is enforced in both directions, with over-long inbound frames
  rejected on the length header *before* the body is read, closing a memory-exhaustion vector.
- A **keep-alive connection pool** reuses established connections, removing a TCP handshake —
  a full extra round trip under emulated delay — from every RPC after the first.
- **Liveness** is tracked by a consecutive-failure counter: a peer is declared down only after
  three consecutive failed RPCs (`fail_threshold = 3`) and any success clears the count, which
  prevents a single transient loss from wrongly evicting a healthy peer.
- Peer hostnames are resolved to IP addresses once and cached, so the hot path never depends on
  the container runtime's embedded DNS.

### 7.2.4 Network emulation

Realistic delay is imposed with the Linux traffic-control facility `tc netem`, applied by
`testbed/netem.sh`. We model a **two-tier** topology of two regions: **5 ms** one-way delay
between nodes in the same region and **50 ms** one-way delay between regions. Because the delay
is applied as egress at both endpoints, the observed round-trip time is approximately `10 ms`
within a region and `100 ms` across regions. Region membership is assigned deterministically by
sorting containers by IP address and taking the index modulo two. The delays are installed with
a classful priority queueing discipline and `u32` filters that match each peer address to its
region's delay band, run inside a throwaway helper container that shares the target's network
namespace, so no node image or Compose definition is modified to emulate the network. A
`verify` sub-command pings a same-region and a cross-region peer and asserts that the two delay
bands are present and cleanly separated.

### 7.2.5 Unbound baseline resolver

The baseline is a single Unbound resolver (`testbed/unbound/`) configured to perform genuine
iterative recursion over the same hierarchy. Its root hints point only at the containerised
root server, and it is given no forwarders and no DNSSEC validation, so it discovers each answer
by walking root → TLD → authoritative exactly as the resolver ring does. One configuration
detail is essential to a fair comparison: Unbound by default discards answers in private address
ranges, so its configuration omits the `private-address` directive, allowing the synthetic
`10.0.0.0/8` answers to survive. Running the same workload against Unbound and against the ring,
over the same hierarchy and the same emulated delays, yields the reference band used throughout
Part A.

### 7.2.6 Workload generator

Queries are produced by `testbed/query_gen.py`, which samples domains according to a **Zipf
popularity distribution with exponent `α = 1.0`** over the rank-ordered served set, so that a
small number of popular names dominate the stream as they do in practice. Queries are issued as
real UDP `A` lookups through the `dnspython` library at a specified offered rate, dispatched by
a closed-loop pool of worker threads (64 by default); each request records one row of
`timestamp, domain, resolver_used, latency_ms, success`, where a query counts as successful only
if the response is `NOERROR` and carries at least one `A` record. In nodes-mode the generator
enters queries into the ring round-robin across all `N` nodes' DNS front ends (`--ring-nodes`),
so that no single node is privileged as the entry point except where an experiment deliberately
fixes the entry node (for example the churn experiment in Part A). A verification mode
(`--check-answers`) additionally compares each answer against the ground-truth manifest and
flags forgeries; it is used only in Part B and is otherwise inert.

## 7.3 Methodology

### 7.3.1 Reproducibility

Every experiment is deterministic given its seed. The canonical pseudo-random seed is **20260919**,
set in `testbed/run_experiment.sh` and mirrored in the workload generator, the Compose generator,
the zone generator, and every analysis script, so that an examiner re-running any experiment
starts from an identical configuration. Each run writes a per-run client CSV under `results/`
named by its parameters and UTC timestamp (`results/exp_<timestamp>_N<n>_q<qps>_d<dur>[_nodes].csv`);
these per-run files are reproducible from the seed and are therefore not themselves committed,
while a one-line summary of every run is appended to the committed manifest
`results/experiments.csv`. Nodes-mode additionally bind-mounts each node's per-node query log to
the host, so that Chord hop counts can be aggregated across the whole ring after a run. The
complete experiment is driven by named one-command scripts — `testbed/run_experiment.sh` for a
single run, and the per-experiment wrappers `experiments/run_a1.sh … run_c5.sh` — each of which
sets the frozen seed by default.

### 7.3.2 Parameter freeze and justification

Before any results were collected, the default parameters were exercised and validated (Phase 4)
and then **frozen** and written down in `results/PARAMETERS.md`, so that every later run — and
any examiner re-run — starts from the same configuration. An experiment departs from these
defaults only where it explicitly sweeps one parameter (for example Part A's replication and
plot-size studies). Table 7.1 lists the frozen set; the justification for each choice follows.

**Table 7.1 — Frozen experimental parameters** (source: `results/PARAMETERS.md` §1).

| Parameter | Value | Set in |
|---|---|---|
| Replication factor `s` | 3 | `node/storage.py` |
| Proof-of-Space challenge timeout `δ` | 2.0 s (test scale) | `gen_nodes_compose.py`, `CHALLENGE_TIMEOUT` |
| Eviction threshold | 3 consecutive failed challenges | `node/pospace_admission.py` |
| Intra-region delay | 5 ms one-way (≈10 ms RTT) | `netem.sh` |
| Inter-region delay | 50 ms one-way (≈100 ms RTT) | `netem.sh` |
| Regions | 2 (assigned by index) | `netem.sh` |
| Per-query timeout | 5.0 s | `query_gen.py` |
| Maintenance interval | 1.0 s | `run_ring_node.py` |
| — stabilize + check predecessor | every round (1.0 s) | `run_ring_node.py` |
| — top-finger refresh / full fix-fingers | ~every 4.0 s | `run_ring_node.py` |
| — periodic Proof-of-Space challenge | ~every 5.0 s | `run_ring_node.py` |
| Plot size `PLOT_N` (test scale) | 1024 leaves | `gen_nodes_compose.py` |
| DRG in-degree `δ` (v3 scheme) | 2 | `gen_nodes_compose.py` |
| Workload | Zipf `α = 1.0` over 1000 Tranco domains | `query_gen.py`, `generate_zones.py` |
| Zone TTLs | 300–3600 s | `generate_zones.py` |
| Warm-up | 30 s ring load (discarded); 15 s for Unbound | `run_experiment.sh` |
| Random seed | 20260919 | `run_experiment.sh` |
| Emulation scale ceiling | N = 32 | Phase 3 decision |

- **Replication factor `s = 3`.** Each DNS chunk is stored on the responsible node and its two
  immediate successors, so that a lookup can survive the loss of individual replicas. Three is
  the smallest factor that still permits a non-trivial agreement among replicas and is the
  figure the thesis design assumes; Part A measures the cost of raising it to 5 and 7, and
  Part B measures the integrity and availability consequences of the replica set.
- **Proof-of-Space challenge timeout `δ = 2.0 s`.** This is the admission and periodic-challenge
  timeout for the small (`PLOT_N = 1024`) plots used in emulation. It is deliberately
  distinguished from the thesis-scale `δ` discussed in Chapter 6 and Phase 1, which depends on
  the final DRG in-degree and awaits cryptographer sign-off; the two must not be conflated. At
  the test plot size a challenge is answered in tens of microseconds, so `2.0 s` is a generous
  separation between an honest prover and a cheater who must recompute.
- **Eviction after 3 consecutive failed challenges.** A single missed challenge may be a
  transient network event rather than a cheating node, so eviction requires three consecutive
  failures; any success resets the count. Part B confirms that a node with a corrupted plot is
  evicted in exactly this many rounds.
- **Two-tier delays 5 ms / 50 ms.** These represent intra- and inter-region round trips of
  roughly 10 ms and 100 ms, spanning the range between same-datacentre and intercontinental
  paths. They are *measured* into every result and are held fixed (not tuned) during simulator
  calibration.
- **Per-query timeout 5.0 s.** A client abandons a query after five seconds and records the
  time-to-failure; this bounds the tail and defines the success criterion under saturation and
  attack. The relationship between this client timeout and the resolver's own behaviour is
  analysed where it matters (for example the tail behaviour under overload in Part A).
- **Maintenance cadence (1.0 s loop; ~4 s finger refresh; ~5 s challenge).** Ring-cycle
  maintenance runs every second so that successor and predecessor pointers recover quickly from
  joins and departures; the more expensive finger-table refresh and the periodic Proof-of-Space
  challenge are spaced out to roughly four and five seconds respectively to keep the maintenance
  load off the query path. The challenge period is deliberately offset from the finger refresh
  so the two do not coincide.
- **Test-scale plot `PLOT_N = 1024`, DRG in-degree 2.** Emulation uses a small plot so that
  dozens of nodes can be built and challenged within a container run; the plot-size dependence
  of admission is studied separately, at realistic sizes, as a microbenchmark in Part A, and the
  thesis-scale plot is characterised in Part C. The DRG in-degree of 2 is the lower end of the
  swept range `{2, 4, 8}` and the frozen default.
- **Workload: Zipf `α = 1.0` over 1000 domains, TTLs 300–3600 s.** A unit Zipf exponent is a
  standard model of web and DNS popularity and produces a realistic mixture of cache hits on
  popular names and DHT or fallback resolutions on rare ones; the TTL ladder ensures records
  expire and are refreshed during longer runs.
- **Warm-up (30 s ring; 15 s Unbound).** The resolver ring is warmed for thirty seconds — enough
  for it to converge and to populate the DHT — before the measured window begins, and the
  warm-up traffic is discarded. The Unbound baseline is warmed for fifteen seconds, since a
  single resolver's cache needs less time to reach steady state. The two warm-up periods are
  distinct and are reported as such.
- **Seed 20260919; emulation ceiling N = 32.** The seed fixes the workload and all randomised
  placement. The emulation ceiling is justified in Section 7.3.3.

### 7.3.3 Emulation and simulation

The reliable ceiling of the emulation on the benchmark machine (Apple M4, 10 cores, 16 GiB RAM)
is **`N = 32` nodes**. At `N = 64` the ring does not reliably converge: lookup success falls to
15–34 % across runs and the ring heals only to roughly 30–44 of 64 correct successors. We
diagnosed this as a **testbed resource limitation, not a protocol defect**. Under the combined
load of query lookups and finger maintenance, the `find_successor` traffic shares the single
event loop with the ring-cycle maintenance, and the frozen Chord `stabilize` drops its successor
on any maintenance RPC that misses its timeout; at `N = 64` the larger initial join-star needs
more convergence rounds, during which the lookup traffic perturbs `stabilize` enough that the
cycle never fully closes. A series of measured fixes outside the frozen code — a connection
pool, consecutive-failure liveness, static-IP addressing, concurrent top-finger refresh, and
staggered joins (Section 7.2.3) — took `N = 8` to full success and made `N = 32` converge
completely, but the clean remedy for `N = 64` would be to make `stabilize` tolerant of a
transient timeout, and that lives in the frozen `chord.py`. We therefore accept `N = 32` as the
emulation scale and carry the large-`N` evidence in the simulator. The examiners asked for
experimental validation, not a specific node count.

The simulator (`sim/`) is a discrete-event model that reuses the protocol logic where possible:
its routing function is a port of the node's own iterative `find_successor`, and it layers the
cache, replicated DHT read with replica agreement, and iterative fallback on top, under the same
Zipf workload over the same Tranco list. Before it is trusted at scale it is **calibrated**
against the `N = 8` and `N = 32` emulation results (`sim/calibrate.py` →
`results/calibration.csv`). The measured 5 ms / 50 ms network is held fixed; only the simulator's
internal processing delays are tuned — a per-hop processing delay of 18 ms (absorbing the
asynchronous-I/O, serialisation, and TCP overhead that the emulation incurs but the simple model
does not), a fallback step of 100 ms, and the charging of each routing hop as a full round trip.
With these levers the simulator reproduces the emulation's end-to-end latency to within **7.7 %**
on every gated metric (for example at `N = 32` the median latency matches to 7.2 % and the 95th
percentile to 7.6 %, and the median hop count of 3 is reproduced exactly;
`results/calibration.csv`). Two limitations are reported rather than hidden: the hop *count* is a
property of topology rather than of delay, so at `N = 8` the simulator's perfectly converged ring
shows a median of 1 hop against the emulation's 2 (the +0.5-hop offset of an imperfectly
converged ring, which does not change the integer median at `N = 32`); and the query model has no
loss term, so its success rate is ≈100 % by construction and is not a calibrated quantity.
Calibrated in this way, the simulator's routing path tracks Chord's `½·log₂N` prediction to
within one hop across `N = 1000`, `5000`, and `10 000` (`results/sim_scale.csv`), which is the
basis for the scalability results in Part A.

## 7.4 Baseline: Unbound reference

We characterise the baseline resolver (Section 7.2.5) under an offered-load ramp, 30 s per load
point with a 15 s warm-up, over the same hierarchy and two-tier delays as the ring. The raw data
are in `results/baseline_unbound.csv`; Table 7.2 summarises them.

**Table 7.2 — Unbound baseline under offered load** (source: `results/baseline_unbound.csv`).

| Offered load (qps) | Success | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|
| 10  | 100.0 % | 3.5 | 132.9 | 214.9 |
| 50  | 100.0 % | 2.0 | 118.0 | 208.0 |
| 100 | 100.0 % | 1.4 | 113.9 | 203.1 |
| 200 | 100.0 % | 1.1 | 5.1 | 201.9 |
| 400 | 96.7 %  | 1.0 | 1.7 | 111.9 |

Two figures define the reference band drawn throughout Part A. First, at an unsaturated offered
load of 10 queries per second, Unbound resolves with a median latency of **3.5 ms** and tail
latencies of **132.9 ms** at the 95th percentile and **214.9 ms** at the 99th. The median is a
warm-cache hit, while the tail reflects cold-cache misses recursing through the emulated
hierarchy, whose cross-region round trip is approximately 100 ms. Second, Unbound sustains at
least 99 % success up to **200 queries per second** (100.0 % at that load); success falls to
**96.7 %** at 400 qps, so saturation lies between 200 and 400 qps in this testbed. We did not
push beyond 400 qps: at 800 qps and above the closed-loop generator's worker pool, rather than
Unbound, becomes the bottleneck, so higher points would measure the generator and not the
resolver. The ceiling at 200 qps and the crossing point are already established, and this band —
a flat low-latency floor and a saturation knee beyond 200 qps — is the yardstick against which
the decentralised resolver's latency and throughput are read in Part A.

(The Unbound latencies quoted here are the dedicated baseline sweep in `results/baseline_unbound.csv`.
Part A draws its reference band from a separate, near-identical three-run measurement collected
alongside the latency-versus-`N` experiment — 95th and 99th percentiles of 132.6 ms and 214.3 ms —
which differs only in the third significant figure; the two agree to within a millisecond.)

As a point of orientation for the results that follow, the decentralised resolver is a wholly
different design operating point: a lookup may traverse several ring hops and read from multiple
replicas over the emulated network, so its latency is naturally higher than a single warm
resolver's, and its value lies in the properties a single resolver cannot offer — Sybil-resistant
decentralised admission and the absence of a single trusted operator — whose costs and benefits
Parts A through C quantify.

## 7.5 Reproducibility statement

The entire evaluation is reproducible from public inputs. Every experiment is seeded with the
fixed value **20260919**, set in `testbed/run_experiment.sh` and mirrored across the workload
generator, the Compose and zone generators, and all analysis scripts. The DNS world is
regenerated bit-for-bit from the vendored Tranco snapshot and a fixed zone-generation seed (with
a fixed SOA serial), so the 1000-domain hierarchy is identical on every machine. Each run emits
a seed-reproducible per-run CSV under `results/`, and a one-line summary of every run is retained
in the committed manifest `results/experiments.csv`; the derived tables and figures cited in this
chapter are likewise committed under `results/`. Every experiment is launched by a named
one-command script — `testbed/run_experiment.sh` and the per-experiment wrappers
`experiments/run_a1.sh … run_c5.sh` — and the frozen parameter set is recorded in
`results/PARAMETERS.md`. Finally, the code that produced the thesis's original measurements —
the plotter `rpos/rpos.py` and the core Chord implementation `node/chord.py` — is byte-identical
to the submitted version; every testbed capability beyond that core was added in new files or
wired through environment variables and runtime overrides, so the reproducibility of the original
results is preserved while the new evaluation is built around them.

## 7.6 Part A — Performance

*Reserved for W2 (issue #57). Latency versus `N`, throughput and saturation, scalability and
per-node load, replication cost, updates, churn, and admission — drawn against the Unbound
reference band of Section 7.4. Sources: `results/A1_…`–`A7_…`.*

## 7.7 Part B — Malicious scenarios

*Reserved for W3 (issue #58). Experimental threat model and the tampering, targeted-placement,
censorship, routing/eclipse, Sybil, malicious-proposer, and denial-of-service attacks across the
adversary-fraction grid. Sources: `results/B0_…`–`B7_…`.*

## 7.8 Part C — Proof of Space: proposed versus Chia

*Reserved for W4 (issue #59). Retention attack on the frozen v3 design, timeout separation under
jitter, detection probability, concrete proof/prover/verifier costs, and the row-by-row
comparison with the "what is lost by gaining efficiency" discussion. Sources: `results/C1_…`–`C5_…`.*
