# testbed/dns — local DNS hierarchy in containers (issue #18 / P3-1)

A self-contained, containerized authoritative DNS hierarchy for the Phase 3 testbed:

```
        root (.)                 dns-root      172.28.0.2
       /        \
   com.          org.            dns-tld-com   172.28.0.3
    |              |             dns-tld-org   172.28.0.4
   (per-domain delegations)
    |              |
  auth1          auth2           dns-auth1     172.28.0.5
 (~half)        (~half)          dns-auth2     172.28.0.6
```

The **referral chain is real**: the root delegates to the TLD servers, each TLD delegates
every domain to one authoritative server (NS + in-bailiwick glue at each hop), and only the
authoritative servers hold the A records (`aa=1`). This is the "real NSD/BIND world" that the
resolver's fallback (`node/query.py` `IterativeResolver`, currently an in-process stub) will
iterate over — wiring that up is a **later** issue, not #18.

## Why NSD

NSD is a pure authoritative server that real root/TLD operators run (NLnet Labs), so the
hierarchy is defensible for the thesis. The referral semantics (NS in AUTHORITY + glue in
ADDITIONAL, `aa=0` at a delegation, `aa=1` at the leaf) are RFC-standard and identical across
NSD/BIND/Knot, so the measured quantity (iterative-resolution hops) does not depend on the
binary. NSD needs one `zone:` stanza per zone; for the ~N leaf zones these are
**machine-generated** by `generate_zones.py` into `zones/zones.auth{1,2}.conf`, so there is no
hand-written boilerplate. Zones are plain RFC 1035 master files, so the same tree can be
re-served by BIND/Knot unchanged if an examiner insists.

The image is built from `alpine:3.20` pinned by manifest digest (see `Dockerfile`) with NSD
from the Alpine 3.20 repo (**NSD 4.9.1** at time of writing) — pinned base + fixed repo
snapshot = reproducible build on the M4/arm64 host and on x86 CI.

## Reproducibility

Everything is reconstructible bit-for-bit from public inputs (CLAUDE.md §2):
- domains come from the **vendored** Tranco snapshot `tranco/tranco_JZNVY_top100k.csv`
  (provenance + sha256 in `tranco/PROVENANCE.md`) in rank order — no network at generate time;
- answer IPs are a pure function of a domain's index (`10.x.x.x`, synthetic/private);
- the auth split is `sha256(domain) % 2` (seed-independent);
- TTLs are drawn from one seeded RNG (`SEED = 1`), ladder `{300,600,900,1800,3600}` s.

Run the generator twice and `diff -r` the outputs — they are identical. `zones/` is
git-ignored (regenerate, don't commit); `MANIFEST.json` records seed, count, Tranco
list ID + CSV sha256, per-TLD selection stats, and the full
`domain -> {tld, auth, answer_ip, ns_ip, ttl}` map (also the hand-off point for the #19
node-wiring seam).

## Run & verify

```bash
cd testbed/dns
python3 generate_zones.py --count 1000            # -> zones/ + MANIFEST.json (deterministic)
docker compose -f docker-compose.dns.yml up -d --build
docker compose -f docker-compose.dns.yml ps
./verify.sh                                        # asserts the done-when via 3 digs
```

`verify.sh` reads a real domain (default `google.com`) from `MANIFEST.json` and walks the
chain, checking a referral at the root and TLD and an authoritative ANSWER at the leaf.

### Manual dig (host)

On **Docker Desktop / macOS** the `172.28.0.0/24` bridge IPs are **not** routable from the
host, so each server is published on a host port (root 5301, com 5302, org 5303,
auth1 5304, auth2 5305):

```bash
D=google.com    # or any domain in MANIFEST.json
dig @127.0.0.1 -p 5301 $D +norecurse   # root -> referral to com   (ANSWER: 0; AUTHORITY: com NS + glue)
dig @127.0.0.1 -p 5302 $D +norecurse   # com  -> referral to auth  (AUTHORITY: ns1.$D + glue -> auth IP)
dig @127.0.0.1 -p 5305 $D +norecurse   # auth2 -> ANSWER           (aa=1; ANSWER: $D A 10.0.0.1)  <= DONE-WHEN
```

On a **Linux host** the container IPs are reachable directly, e.g. `dig @172.28.0.5 $D`.
A full one-shot recursive `+trace` needs a resolver seeded with our root as its only hint —
that is #19's Unbound; do not build it here.

```bash
docker compose -f docker-compose.dns.yml down     # tear down
```

## Scaling (note for Phase 6, out of scope for #18)

`--count` defaults to 1000 (issue #18) but scales toward the 10k–100k range CLAUDE.md Phase 3
mentions. The vendored snapshot holds 45507 `.com` / 4500 `.org`; past ~9000 domains the
`.org` half runs short and the generator fills from `.com` (logged in `MANIFEST.json`). The
per-domain-zone model means each auth server loads `N` zone files; NSD handles it but
startup/memory grow — at large `N`, consolidating domains into fewer master files may scale
better.

## Files

| Path | What |
|---|---|
| `topology.json` | single source of truth: server names -> static IPs, subnet |
| `generate_zones.py` | fixed-seed zone/config generator (stdlib only) |
| `tranco/` | vendored Tranco snapshot + provenance |
| `nsd/*.nsd.conf` | static per-server NSD configs (auth ones `include:` a generated file) |
| `Dockerfile` | pinned alpine + nsd (one image, all five roles) |
| `docker-compose.dns.yml` | the 5-container tier (foldable into #19's master compose) |
| `verify.sh` | done-when checker (3-dig referral chain) |
| `zones/` | **generated**, git-ignored; `MANIFEST.json` is the reproducibility artifact |
