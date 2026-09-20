# testbed/

Phase 3 — the emulation testbed: containerized local DNS hierarchy, N resolver nodes, an
Unbound baseline resolver, and (later) `tc netem` link delays + a Zipf query generator for
one-command end-to-end experiments.

## Layout

| Path | What | Issue |
|---|---|---|
| `dns/` | the authoritative DNS hierarchy (5 NSD servers: root + com/org TLDs + auth1/auth2) | #18 |
| `docker-compose.yml` | **master compose**: `include`s the DNS tier and adds Unbound + N nodes + query-gen | #19 |
| `up.sh` | one-command bring-up: generate zones if missing, then `up --scale node=N` | #19 |
| `verify.sh` | done-when checker: all containers Up + Unbound recursion returns the MANIFEST answer | #19 |
| `node/` | the resolver-node image (`Dockerfile` + `requirements.txt`) | #19 |
| `unbound/` | the recursive-resolver image (`Dockerfile`, `unbound.conf`, `root.hints`) | #19 |
| `netem.sh` | apply/verify/clear `tc netem` link delays (5ms in-region, 50ms cross-region) | #20 |
| `netem-helper/` | the throwaway image `netem.sh` runs in each container's netns to program `tc` | #20 |
| `query_gen.py` | Zipf(α=1.0) DNS query generator → per-query CSV (latency/success) | #21 |
| `run_experiment.sh` | **one-command runner**: up → health → netem → warm-up → load → summary → down | #22 |

## Full testbed (issue #19)

One isolated bridge network `dnsnet` (`172.28.0.0/24`) carries everything:

```
dns-root .2 ─┬─ dns-tld-com .3 ─┬─ dns-auth1 .5
             └─ dns-tld-org .4 ─┴─ dns-auth2 .6      (authoritative tier, issue #18)

unbound .7         recursive resolver — recurses over the tier above
node (×N)          rpos resolver nodes — dynamic IPs 172.28.0.129+
query-gen          in-network dig box (placeholder for the #21 Zipf generator)
```

### Run

```bash
cd testbed
./up.sh 8            # build + start the whole world with 8 resolver nodes (default 8)
./verify.sh          # assert the done-when
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml down    # tear down
```

`up.sh` regenerates the (git-ignored) DNS zones via `dns/generate_zones.py --count 1000` if
`dns/zones/MANIFEST.json` is absent. **N** is a CLI argument (`./up.sh 16`), not a value in
the compose file — it is passed to `docker compose --scale node=N`, because Compose cannot
combine `--scale` with a static IP or `container_name` and scaffold nodes need neither yet.

### Link delays (issue #20)

By default every container-to-container hop is ~0ms. `netem.sh` emulates a two-tier network
over `dnsnet` with `tc netem`: **5ms within a region, 50ms cross-region**. Containers are
assigned to regions **by index** (sorted by IP, `region = index % REGIONS`, default 2 regions)
— deterministic for a given running set.

```bash
cd testbed
./up.sh 8                # bring the world up first
./netem.sh apply         # print the region table + program tc in every container
./netem.sh verify        # ping a same- and a cross-region peer; assert RTT (done-when)
./netem.sh show          # inspect each container's qdisc + filters
./netem.sh clear         # remove all netem qdiscs
```

Delays are **one-way per direction**, applied at both endpoints, so the **ping RTT is ~2×** the
configured number: same-region ≈ 10ms, cross-region ≈ 100ms (`verify` asserts this). Config via
env: `SAME_MS` (5), `CROSS_MS` (50), `REGIONS` (2), `IFACE` (eth0), `PING_COUNT` (10),
`NETWORK` (`rpos-testbed_dnsnet`).

`netem.sh` needs **no changes to any real image or the compose files**: `tc`/`ping` and the
`NET_ADMIN` capability come from a tiny helper image (`netem-helper/`) run inside each target
container's network namespace (`docker run --net=container:<id> --cap-add=NET_ADMIN`). The #18
DNS tier and the #19 images stay byte-identical (CLAUDE.md §2). Applies to **all** containers on
`dnsnet` (nodes + Unbound + query-gen + the 5 DNS servers), so node↔node and Unbound↔hierarchy
links are both emulated. Run `verify` **before** `apply` to see the ~0ms baseline.

### Query generator (issue #21)

`query_gen.py` drives load for the Phase 6 performance experiments: it emits DNS A queries
following a **Zipf(α=1.0)** popularity distribution over the testbed's 1000 served domains and
writes one CSV row per query.

```bash
cd testbed
# done-when smoke test (no testbed needed — queries just fail, CSV is still valid):
python3 query_gen.py --qps 10 --duration 10 --output /tmp/test.csv

# real run against the testbed's Unbound (bring the world up first with ./up.sh N):
python3 query_gen.py --qps 50 --duration 30 --resolver 127.0.0.1 --port 5300 \
        --output ../results/unbound_50qps.csv
```

CSV schema: `timestamp,domain,resolver_used,latency_ms,success` (epoch-seconds float
timestamp; `success` = NOERROR response carrying an A record). Key args: `--qps`,
`--duration`, `--output` (required); `--resolver`/`--port` (default `127.0.0.1:5300`, the
Unbound host port), `--resolver-name` (label for `resolver_used`), `--alpha` (default 1.0),
`--seed` (default 20260919 — sampling is reproducible), `--timeout` (default 5.0s).

**Domains** are read from `dns/zones/MANIFEST.json` when present (the exact served set), else
reproduced identically from the vendored Tranco list via `dns/generate_zones.py` (so it works
on a fresh clone). Either way they are ranked by **real Tranco popularity** — rank 1
(`google.com`) is the most-queried — so the ordering is identical regardless of source.

> **Standalone (scaffold scope).** This is the generator script only; wiring it into the
> compose network (replacing the idle `query-gen` placeholder with a Python-capable image) is
> a deferred follow-up. Until then, run it from the host against `127.0.0.1:5300`.

### One-command experiments (issue #22)

`run_experiment.sh` chains the four scripts above into a single end-to-end run with **no manual
steps** (the Phase 3 done-when): bring up → wait for health → apply `netem` → warm up → drive
`query_gen` → summarise → tear down.

```bash
cd testbed
./run_experiment.sh --nodes 8 --qps 20 --duration 15
# one-line summary, e.g.:
# [run_experiment] N=8 qps=20 dur=15 netem=on mode=host rows=300 ok=300 (100.0%) \
#   ach=20.0qps p50=2.1 p95=8.4 p99=15.2 ms -> results/exp_20260920-...Z_N8_q20_d15.csv
```

Per-query CSVs land in **`../results/`** (`exp_<UTC-timestamp>_N…_q…_d….csv`) and one summary
row per run is appended to **`../results/experiments.csv`** for Phase 6 aggregation.

Key options: `--nodes N` [8], `--qps` / `--duration` (required), `--warmup S` [30],
`--seed S` [20260919], `--alpha` [1.0]; `--no-netem`, `--regions`/`--same-ms`/`--cross-ms`;
`--resolver`/`--port` (force host mode), `--output-dir`, `--health-timeout` [180], `--keep-up`;
`--help` prints the full banner.

**What it measures.** Only Unbound is live end-to-end (nodes are still scaffold singletons —
see below), so this is the **Unbound baseline** (Phase 4/6 A1), not the DHT resolver.

**Resolver path (two modes, chosen automatically).** By default the load runs on the **host**
against `127.0.0.1:5300`. After the health gate the script probes that port once; if it's dead
(the documented macOS Docker Desktop host-forward quirk, which would otherwise give an
all-failure CSV) it falls back to **in-network** mode — `query_gen` inside a throwaway
`rpos-node:latest` container on `dnsnet`, straight at Unbound `172.28.0.7:53` (that image
already ships `dnspython`, so no pip install). Passing `--resolver` forces host mode.

> **netem caveat.** `netem.sh` programs delays for the containers present when it runs, so the
> Unbound↔hierarchy links *are* delayed in both modes. The client↔resolver hop is not: the host
> isn't a container, and the in-network throwaway box joins `dnsnet` *after* `netem apply` (its
> dynamic IP isn't in the peers' filters). Both modes therefore share an undelayed client hop —
> consistent, but it slightly understates end-to-end latency.

### What is genuinely live — and what is deliberately deferred

**Live end-to-end:** Unbound performs real iterative recursion (root → TLD → authoritative)
over the #18 hierarchy. `dig`ging a MANIFEST domain returns the exact synthetic `10.x` answer
for that domain:

```bash
# in-network (works on every platform — the authoritative check):
docker compose -f docker-compose.yml exec query-gen dig @unbound google.com +short   # -> 10.0.0.1

# from the macOS/Linux host (published on loopback:5300):
dig @127.0.0.1 -p 5300 google.com +short
```

> **Deliberately deferred (scaffold scope).** The N `node` containers each build a **real v3
> DRG PoSpace plot** and stay alive (a bare TCP liveness port on 9910 backs the compose
> healthcheck), but they do **NOT** form a Chord ring or answer DNS across containers.
> `node/net.py` is an **in-process** message bus only — there is no cross-container transport
> yet. Real node-to-node RPC (host:port addressing, wire serialization of RPC args incl.
> PoSpace proofs, a background stabilize/challenge loop) and binding the DNS interface to a
> real UDP socket are tracked in a **separate follow-up issue** and are out of scope for #19.
> Until then, the nodes are honest singletons and only **Unbound** resolves over the tier.

### Node configuration (env vars on the `node` service)

`PLOT_N` (default 1024), `DRG_INDEGREE` (2), `CHALLENGE_TIMEOUT` (2.0 s), `SEED` (20260919),
`MALICIOUS_MODE` (`honest`|`lie`|`drop`|`misroute`|`forge`). `NODE_INDEX` is unset by default:
scaled replicas derive a distinct identity by hashing their container hostname (set
`NODE_INDEX` only to run a single fixed node). The node image bundles both `node/` and
`phase1/` (the v3 PoSpace scheme is imported from `phase1/` by relative path, never copied).

## Notes / gotchas

- **Always bring the testbed up through the master compose** (`./up.sh` / `docker compose -f
  docker-compose.yml ...`). `include:` copies the DNS tier's services + network into this
  project (`rpos-testbed`); it does **not** attach to a separately-running `rpos-dns` project.
- **Static vs dynamic IPs.** The network pins `ip_range: 172.28.0.128/25` so Docker's dynamic
  assignments (the scaled `node` service) stay in the upper half of the /24 and cannot grab
  the static IPs `.2–.7` before `dns-root`/`unbound` start. (Docker's IPAM does not reserve
  static addresses from the dynamic pool — without this the containers race for `.2`/`.7` and
  fail with *"Address already in use"*.)
- **Unbound + `10.x` answers.** `unbound.conf` must **never** contain a `private-address:`
  line — every synthetic answer is in `10.0.0.0/8` and Unbound would strip it (empty
  NOERROR). The resolver is left open (`access-control: 0.0.0.0/0 allow`, matching the #18
  NSD servers) with its host port bound to loopback.
- **macOS Docker Desktop** cannot route the `172.28` bridge IPs from the host; use the
  published `127.0.0.1:5300` for host `dig`, or the in-network `query-gen` box for the
  definitive check.
