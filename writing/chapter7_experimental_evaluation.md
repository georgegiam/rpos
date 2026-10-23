<!--
  Chapter 7 — Experimental Evaluation (Phase 9, W1: issue #56)
  Scope of this file: §7.1–§7.5 (testbed, methodology, parameter justification, baseline)
  and §7.6 (Part A — performance results A1–A7, drafted by W2 / issue #57).
  §7.7–§7.8 (Parts B/C results) are reserved stubs, drafted by W3–W4.

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

Part A answers examiner point **(iii)**: the latency, throughput, and scalability of the *whole*
resolver, measured rather than projected. Seven experiments (A1–A7) are reported. Each is run on
the testbed of Section 7.2 at the `N = 32` emulation ceiling and, where scale demands it, carried
into the thousand- to ten-thousand-node regime by the calibrated simulator of Section 7.3.3; each
is read against the Unbound reference band of Section 7.4, and every quantitative claim names the
`results/` CSV it is drawn from. Unless an experiment states otherwise, the frozen parameter set of
Table 7.1 applies — replication factor `s = 3`, the two-tier 5 ms / 50 ms network, a Zipf `α = 1.0`
workload over 1000 Tranco domains, and seed `20260919` — and every departure from it (the
replication and plot-size sweeps, the throughput cache control, the churn schedule) is wired
through environment variables and runtime overrides that leave the frozen `rpos/rpos.py` and
`node/chord.py` byte-identical.

### 7.6.1 Latency versus ring size (A1)

We measured client-observed resolution latency at `N ∈ {4, 8, 16, 32}`, three runs per size (five
at `N = 32`), at an unsaturated offered load of 10 queries per second. Each query is additionally
classified by the outcome the serving node logged — a local **cache hit**, a **DHT hit** routed to
and read from the responsible replicas, or an iterative **fallback** to the DNS hierarchy with
store-back — by joining the client log to the per-node log within each (serving node, domain)
bucket; the join matches 99.9–100 % of rows. Table 7.3 reports the percentile latencies per
outcome and overall, and Figure 7.1 draws them against the flat Unbound band.

**Table 7.3 — Resolution latency by ring size and outcome** (source: `results/A1_latency_vs_N.csv`;
`rpos` success ≥ 99.2 % at every `N`, Unbound 100 %).

| `N` | Outcome | Share (%) | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|
| 4  | all       | 100.0 | 4.8   | 650.4  | 726.6  |
| 4  | cache hit | 50.9  | 3.2   | 4.1    | 5.0    |
| 4  | DHT hit   | 18.9  | 319.5 | 351.8  | 411.7  |
| 4  | fallback  | 30.1  | 496.5 | 686.5  | 850.1  |
| 8  | all       | 100.0 | 270.6 | 887.9  | 1300.0 |
| 8  | cache hit | 42.2  | 2.8   | 4.2    | 6.9    |
| 8  | DHT hit   | 27.2  | 346.8 | 661.8  | 669.4  |
| 8  | fallback  | 30.6  | 681.3 | 1171.2 | 1327.7 |
| 16 | all       | 100.0 | 335.3 | 972.1  | 1295.7 |
| 16 | cache hit | 32.9  | 2.4   | 4.4    | 6.7    |
| 16 | DHT hit   | 36.6  | 354.7 | 736.5  | 768.4  |
| 16 | fallback  | 30.4  | 723.2 | 1218.0 | 1495.7 |
| 32 | all       | 100.0 | 510.6 | 1495.3 | 2737.4 |
| 32 | cache hit | 24.9  | 1.3   | 4.2    | 5.2    |
| 32 | DHT hit   | 44.4  | 485.4 | 1143.7 | 2207.8 |
| 32 | fallback  | 30.4  | 1030.5| 1977.1 | 3308.1 |
| —  | Unbound (band, all `N`) | — | 3.5 | 132.6 | 214.3 |

**Figure 7.1 — Resolution latency versus ring size, split by outcome, against the Unbound band**
(`results/fig_A1_latency_vs_N.png`; source: `results/A1_latency_vs_N.csv`).

A cache hit is essentially a local operation — a median of 1.3 to 3.2 ms, flat in `N` and in fact
below Unbound's own warm median of 3.5 ms — because it touches no ring traffic. A DHT hit or a
fallback, by contrast, pays Chord routing and so grows with ring size: the DHT-hit median rises
from 319.5 ms at `N = 4` to 485.4 ms at `N = 32`, and the fallback median from 496.5 ms to
1030.5 ms, consistent with the `≈ ½·log₂N` hop growth of Chord [CITE: Stoica-Chord]. The crucial
point is that the *overall* median is governed by the shifting mixture of outcomes, not by any one
path slowing in isolation: as `N` grows the cache-hit share falls from 50.9 % to 24.9 % and the
median migrates toward the DHT and fallback cost, lifting the overall p50 from 4.8 ms to 510.6 ms.
The decentralised tail is three to eight times Unbound's — the expected price of iterative routing,
majority-voted replica reads, and store-back over the emulated network — while the cache path
remains competitive with a mature single resolver.

One tail behaviour is reported rather than smoothed. At `N = 32` the 99th percentile is genuinely
noisy: extending the experiment from three runs to five did not tighten it, because the slowest DHT
and fallback queries sit right against the 5 s client timeout, so whether a handful of queries in a
given run cross that ceiling swings the p99 by close to a second. The run-to-run standard deviation
of the overall p99 is 43 % of its mean (a 2737.4 ms mean with a 1174.8 ms standard deviation; the
DHT-hit and fallback series are 41 % and 43 %), against a 30 % noise threshold, and this caveat is
carried in the `note` column of the N = 32 rows of the CSV. The p50 and p95 are stable and are the
reliable headline; any claim that leans on the `N = 32` p99 must quote it with this spread.

### 7.6.2 Throughput and saturation (A2)

Measuring the resolver's throughput honestly required first removing a methodological confound. An
earlier ascending load sweep on a single long-lived ring let the node caches accumulate across load
points, so the measured p95 *fell* as the offered rate rose (from 1774 ms at 50 qps to 8.9 ms at
100 qps) and the apparent saturation point drifted with however warm the cache happened to be: that
sweep measured cache accumulation, not saturation, and its readings are superseded. The redo pins
the cache state with a new `UPSTREAM_TTL` knob in `node/run_ring_node.py` (default 300 s, so A1 and
A3–A7 are byte-identical and no frozen source is touched) and reports two clean curves at `N = 32`:
a **COLD-PATH** curve (`UPSTREAM_TTL = 0`, so every lookup re-enters the DHT read path) and a
**STEADY** curve (`UPSTREAM_TTL = 100000`, so every lookup is served from a warm cache). The
node-side outcome mix confirms the pin exactly — 100 % DHT hits on the cold curve and 100 % cache
hits on the steady curve, with a cache-share standard deviation of 0.0 pp at every level — and the
achieved rate tracks the offered rate to within ±0.05 qps even at 300 qps, so a failure is genuine
ring saturation and not a generator limit. Figure 7.2 shows both curves.

**Figure 7.2 — Throughput: success rate and p95 latency versus offered load, cold DHT path versus
warm cache** (`results/fig_A2_throughput.png`; source: `results/A2_throughput.csv`).

The cold DHT path exercises the full read cost of the design — route, read three replicas, and vote
— on every query, and it saturates (the first load point below 95 % success) at **250 queries per
second**, its success declining monotonically from 99.9 % at 25 qps to 92.8 % at 300 qps while its
p95 stays flat at roughly 650 ms. The warm cache path shows **no saturation through 200 qps**,
holding 100 % success with a p95 of about 1 ms. The gap between the two curves is the quantified
value of caching: the p95 differs by about 650-fold at matched mid-range load (653.4 ms against
1.0 ms at 150 qps), and the raw DHT path saturates at roughly a quarter of the 200+ qps Unbound
sustains over the same hierarchy (Section 7.4). Two bounds on the result are stated rather than
hidden. Queries enter at a single node (node 0, as in the churn experiment) so that its cache is
coherent and fully controllable; and an exploratory cold run with queries distributed across all 32
entry points gave non-monotonic, unstable success (82 %, 96 %, 75 % at 25, 50, 75 qps) and was
discarded, because sustained pure-DHT load from every node perturbs the frozen Chord maintenance
loop into reconverging mid-measurement — the same `chord.py` fragility documented for `N = 64`
(Section 7.3.3), not a queueing signal. The reported cold number is therefore a single-entry DHT
saturation point, and the distributed path is more fragile still.

### 7.6.3 Scalability and per-node load (A3)

Scalability is the question of what happens to each node's work as the ring grows under a fixed
external load. We held the offered load at 50 queries per second — below the saturation knee of
Section 7.6.2 — and measured the emulation at `N ∈ {4, 8, 16, 32}` while the calibrated simulator
carried the same experiment out to `N = 10 000`. Because the emulation has no wire-level message
counter, per-node load is computed on both sides by the *same* model: the simulator's
`ring_round_trips(outcome, hops)` accounting (a cache hit costs no ring messages, a DHT hit costs
`route + 1 + s` round trips, a fallback twice that, with `s = 3` and a round trip counted as two
messages) is applied identically to the measured emulation outcomes, so the two series are directly
comparable. Figure 7.3 plots the result.

**Figure 7.3 — Per-node message load and throughput versus ring size, emulation and simulation**
(`results/fig_A3_scalability.png`; source: `results/A3_scalability.csv`).

Per-node message load **falls monotonically as the ring grows**, which is the scalability property
the design claims: a fixed query load is spread over more nodes while each query still touches only
`O(log N)` of them. The decay is about 0.62× per doubling of `N` on both sides — from 75.4 to 48.4
to 28.7 to 17.7 messages per node per second across `N = 4` to `32` in emulation, and from 43.0 to
29.4 to 19.5 to 12.5 in the simulator — and the simulator continues the same slope out to just
**0.12 messages per node per second at `N = 10 000`**, while throughput stays flat near the offered
rate (emulation goodput 47.4 to 50.0 qps). The emulation points sit about 1.5 to 1.8 times above
the simulator overlay at matching `N`: this is an absolute-level offset from cold-start cache
warmth — the 30 s warm-up at 10 qps touches only about 300 of the 1000 Zipf domains, so the measured
window still carries more first-time DHT and fallback lookups than the simulator's idealised steady
state — and not a difference in slope. The scalability claim is the slope, on which the two agree.
The model counts query-path RPCs only and excludes maintenance traffic, identically on both sides;
and `N = 32`, the emulation ceiling, shows 94.8 % success at this heavier 50 qps load, consistent
with the throughput result of Section 7.6.2.

### 7.6.4 Cost of replication (A4)

Replication is the mechanism behind both the integrity vote and the availability of the DHT, and
A4 isolates its *cost* by sweeping the replication factor `s ∈ {3, 5, 7}` at `N = 32` and 10 qps
with no induced failures. Table 7.4 reports the result; the raised factors are supplied through a
runtime `SUCC_LIST_LEN` override that leaves `node/chord.py` byte-identical, and the `s = 3` row
reproduces the `N = 32` operating point of A1 and A3.

**Table 7.4 — Cost of replication at `N = 32`, 10 qps** (source: `results/A4_replication.csv`).

| `s` | Source | Messages / query | p50 (ms) | p95 (ms) | Success (%) |
|---|---|---|---|---|---|
| 3 | emulation | 13.14 | 473.3 | 1421.5 | 99.8 |
| 5 | emulation | 17.47 | 577.1 | 2370.6 | 97.1 |
| 7 | emulation | 21.21 | 725.9 | 2753.4 | 90.1 |
| 3 | simulation | 13.46 | 320.5 | 1300.0 | 100.0 |
| 5 | simulation | 17.62 | 320.5 | 1300.0 | 100.0 |
| 7 | simulation | 21.79 | 320.5 | 1300.0 | 100.0 |

At steady state, with no replica actually failing, higher replication is **cost on every axis**. The
message count per query rises roughly linearly in `s`, by about two messages per added replica — 13.14
to 17.47 to 21.21 in emulation, matching the simulator's independent accounting (13.46 to 17.62 to
21.79) to within about 3 % and so validating the shared message model. The emulation median latency
rises from 473.3 ms to 725.9 ms because `node/storage.py` reads replicas **sequentially** over the
emulated network, adding one round trip per replica; the simulator, which models the replica fan-out
as parallel, stays flat at 320.5 ms, a deliberate and documented divergence that makes the emulation
the headline for the latency trend and the simulator a message-model cross-check. Success *falls*
from 99.8 % to 90.1 %, because with no failures the extra replicas add no availability while the
lengthening sequential-read tail crosses the 5 s client timeout. This is the cost side only: higher
`s` also multiplies storage by `s`, and its availability *benefit* appears only when replicas
genuinely depart, which the churn experiment of Section 7.6.6 measures. (The simulator's uniform
100 % success reflects its lack of a loss model, not a real result.)

### 7.6.5 Cost of updates (A5)

A record is updated through the Algorithm 3 ledger: a proposer locates the responsible node, runs a
two-phase commit (pre-commit then commit) across the `s` replicas, and appends one hash-chained,
tamper-evident entry per replica. A5 measured 50 real updates driven from node 0 at `N = 32`,
`s = 3`, over three runs, counting messages on the wire and reading the ledger length across all 32
nodes before and after. Table 7.5 reports it.

**Table 7.5 — Cost of a ledger update at `N = 32`, `s = 3`, 50 updates** (source:
`results/A5_updates.csv`).

| Metric | Emulation (measured) | Simulation (model) |
|---|---|---|
| Updates committed | 50 / 50, every run | — |
| Commit latency p50 / p95 / p99 (ms) | 583.0 / 834.4 / 866.6 | 438.5 / 646.5 / 826.5 |
| Messages per update (round trips) | 22.08 (11.04) | 18.75 (9.38) |
| Ledger entries appended | 150 (= 50 × `s`) | — |

A coordinated, auditable update is sub-second at test scale: the emulation commits with a median of
583.0 ms (standard deviation 3.2 ms over three runs), dominated by the two majority round trips to
the replicas on top of the Chord lookup. The measured cost runs above the simulator's 438.5 ms model
for two reasons the model makes explicit — `propose_update` issues its per-replica calls
sequentially where the simulator models each phase as a parallel fan-out, and the emulation ring
routes about half a hop above the theoretical optimum. The wire count of 22.08 messages per update
(11.04 round trips) decomposes cleanly as one locate plus `2·s` replica round trips, and lands above
the simulator's logical 18.75 because the extra locate round trips from the half-hop routing offset
outweigh the self-directed calls the wire count elides. The ledger grew by exactly **150 entries =
50 × `s`** on every run, verified ring-wide, which is the price of a verifiable audit log: one
chained entry per replica per committed update. Because all 50 updates came from a single proposer to
distinct domains there was no lock contention and no abort, so the abort path is exercised only by the
unit tests and the simulator's self-test; and the update latency is the one path the simulator
calibration (Section 7.3.3) does not fit, so the emulation figures are the measured headline and the
simulator is an analytic lower bound. (The simulator's 44 847-entry growth reflects a two-hour
horizon that folds in TTL-expiry refreshes, not the 50-update workload.)

### 7.6.6 Resilience under churn (A6)

Churn tests whether the resolver stays available as nodes join and leave. A host-side injector
`docker kill`s and `docker start`s ring containers on a seeded alternating-renewal schedule, with a
mean uptime swept over `{30, 60, 120, 300, ∞}` seconds and a mean 5 s downtime; the bootstrap seed
(node 0) is never churned and all measured queries enter at node 0, so that a miss reflects the
*unavailability of data or routes* rather than the client simply having addressed a dead node.
Figure 7.4 reports lookup success against mean session length.

**Figure 7.4 — Lookup success versus mean node session length** (`results/fig_A6_churn.png`; source:
`results/A6_churn.csv`).

Replication and the DNS-hierarchy fallback together keep the resolver available under churn. The
raw-DHT success rate — the stricter headline, which counts only lookups answered from the DHT itself
— degrades only gently as sessions shorten, from 76.30 % with no churn to 74.81, 72.89, 72.73, and
70.73 % at 300, 120, 60, and 30 s mean sessions, a decline of about 5.6 pp (run-to-run standard
deviation ≤ 1.1 pp) even at roughly one departure per second. End-to-end success, which the user
actually observes, stays at or above 96 % throughout (99.97 % with no churn, 97.42 % at 30 s
sessions), because the fallback re-fetches whatever churn evicts. The visible cost of heavy churn is
therefore tail latency, not correctness: the median stays cache-flat at 1.6 to 2.9 ms while the p95
nearly doubles under 30 s churn, from 938.5 ms to 1693.2 ms, as stale-routing retries accumulate.

The 76.30 % no-churn anchor needs care, and A6 resolves it directly: it is **cold-start warming, not
a routing or availability gap**. Splitting the no-churn miss per domain in time order attributes
23.5 % to cold population (the first touch of an un-warmed Zipf-tail domain, where the DHT is
genuinely empty and the query correctly falls back and stores the answer) and only **0.19 % to a
populated-but-failed lookup** — and even that 0.19 % is an upper bound, since the few events are two
client queries racing on the same two domains 108 ms and 485 ms apart, before the store-back lands,
which is itself cold-start. The churn effect is thus the *decline below* the anchor, not its absolute
level; the mean live population tracks the injector's model (27.8 rising to 32.0 nodes against a
predicted ≈ 27.6 at 30 s), confirming the churn occurred at the intended rate. The simulator, which
models data availability with active 1 s re-replication and no cold-start, is accordingly more
optimistic (96.9 % at 30 s rising to 100 %) and serves as a directional cross-check rather than a
fitted match: the emulation has no repair loop (a departed node's chunks are restored only when a
later query re-fetches and stores them), so it is the pessimistic real-system view, and the
cold-population split is exact only at the no-churn point.

### 7.6.7 Cost of admission (A7)

Admission is the Proof-of-Space gate every joining node must pass: build the v3 DRG plot, commit it
with a Merkle tree, and answer a challenge. Because at these node counts a container run would bury
the ~100 ms plot-size signal under seconds of startup and convergence noise, A7 is a microbenchmark —
it times the node's *exact* admission functions over the eight real ring keys and cross-checks them
against a real in-process eight-node ring performing genuine `create()`/`join()` — rather than a
Docker experiment. Figure 7.5 plots join time against plot size on log-log axes.

**Figure 7.5 — Admission (join) time versus plot size, with the Merkle-commit and challenge
decomposition** (`results/fig_A7_admission.png`; source: `results/A7_admission.csv`).

Admission cost is **plot-bound and linear in the plot size** (`O(N)` in the number of leaves). At
the default DRG in-degree `δ = 2`, plotting dominates and scales as one SHA-256 per leaf — 1.59,
6.54, 26.01, and 106.20 ms across plot sizes `2^10` to `2^16`, a clean factor of about 4 per
four-fold size step (slope 1 on the log-log axes). The Merkle commitment is the second cost at about
15 to 17 % of plotting (0.29 to 18.32 ms) and is independent of `δ`, while the challenge itself — proving
and verifying — is negligible, a few tens of microseconds (prove ≈ 4 to 22 µs, verify ≈ 11 to 50 µs)
because it opens only `1 + δ` Merkle paths regardless of plot size, leaving roughly five orders of
magnitude of headroom under the 2 s admission timeout so that an honest joiner is never rejected on
time. That the decomposition is faithful to the real path is confirmed by the in-process ring, whose
end-to-end `join()` matches the summed component cost to within about 4 % (129.55 ms against
124.54 ms at `2^16`); the small roughly-constant excess is the `find_successor` lookup, so the
network part of admission is a modest additive constant and plotting is what grows. Raising `δ` buys
depth-robustness at a cost on every axis — at `2^16` the plot grows to 106.20, 214.84, and 438.72 ms
and the proof to 1632, 2720, and 4896 bytes for `δ = 2, 4, 8` — and a native implementation would cut
the plot time by a further factor of 33 to 55 (a 3.22 ms floor at `δ = 2`, `2^16`). These are
test-scale plots (`≤ 2^16` leaves); the thesis-scale plot of `N = 3.36 × 10^9` leaves (~200 GiB) and
its out-of-core regime are characterised in Part C.

## 7.7 Part B — Malicious scenarios

*Reserved for W3 (issue #58). Experimental threat model and the tampering, targeted-placement,
censorship, routing/eclipse, Sybil, malicious-proposer, and denial-of-service attacks across the
adversary-fraction grid. Sources: `results/B0_…`–`B7_…`.*

## 7.8 Part C — Proof of Space: proposed versus Chia

*Reserved for W4 (issue #59). Retention attack on the frozen v3 design, timeout separation under
jitter, detection probability, concrete proof/prover/verifier costs, and the row-by-row
comparison with the "what is lost by gaining efficiency" discussion. Sources: `results/C1_…`–`C5_…`.*
