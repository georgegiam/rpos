#!/usr/bin/env bash
# Issue #44 [B3] — Censorship: data collection (Phase 7, examiner point (ii)).
#
# B3 holds the ring FIXED at N=32 (frozen emulation ceiling, PARAMETERS.md §1), s=3, 10 qps, and
# makes a fraction f of the nodes MALICIOUS (MALICIOUS_MODE=drop -> node/malicious.py's _should_drop
# black-holes every inbound RPC: storage reads/writes, routing AND maintenance). A drop node reads
# to the ring like a dead/eclipsed node that Chord heals around (cf. A6 churn). It measures whether
# domains still resolve, and at what added latency, swept over f, against the censorship bound (a
# chunk's DHT read is DENIED only when ALL s=3 of its replicas drop -> f^s; one honest replica
# rescues the majority vote). This script ONLY collects raw data; the table / plot are produced by
# experiments/b3_censorship.py.
#
# TWO PLACEMENT BLOCKS (mirroring B1):
#   random   — f in {0,10,20,30,40,50}% -> n_mal = round(f*32) = {0,3,6,10,13,16} chosen uniformly
#              from indices 1..31 (node 0, the seed/entry anchor, stays honest). Placement is
#              RESAMPLED per run (seed = SEED+run). f=0 is the HONEST CONTROL (epic cross-cutting
#              requirement: if the effect vanishes at f=0 it was chord.py fragility, not the attack).
#   targeted — co-locate drop on ALL s replicas of ONE popular chunk, so that chunk's DHT read is
#              denied regardless of the global f. The worst-case censorship demo: measure whether it
#              still resolves (fallback) and at what latency. (Feasibility of achieving such
#              placement by id-grinding is B2.)
#
# THE NEW DRIVER (no frozen edit, CLAUDE.md §2): experiments/b3_placement.py computes WHICH node
# indices are malicious (host-side, reproducible from (N,s,seed); reuses B1's ring/replica model);
# gen_nodes_compose.py's --malicious-indices + --malicious-mode drop (threaded via the new
# run_experiment.sh --malicious-mode passthrough, default lie so B1 stays byte-identical) makes
# exactly those nodes drop. query_gen.py's default success/latency columns ARE the B3 metric — no
# --check-answers (that is B1's forgery column). node/* and rpos/rpos.py are untouched (the drop
# behaviour already exists).
#
# METHODOLOGY — B1's proven bring-up (warm @ 10 qps, measure, snapshot ring logs WHILE UP):
# per (block, point, run) bring up N=32 with the computed --malicious-indices --malicious-mode drop,
# converge + warm @ 10 qps ONCE (--keep-up), truncate node logs to scope the window, drive the
# measured load with --ring-nodes 1 (queries enter the HONEST seed node 0 only — so fallback is
# always available and the measured signal is the DHT-layer censorship, not "asked a dead node"; a
# drop node AS entry bypasses _should_drop anyway), snapshot client.csv + each node's queries.csv
# (node 0's is the raw-DHT outcome signal: cache_hit / dht_hit / fallback) while up, then tear down.
#
# Frozen B3 workload (PARAMETERS.md): N=32, s=3, measured 10 qps, 120 s measured, 30 s warm-up @
# 10 qps, Zipf alpha=1.0 over 1000 Tranco domains, netem 5/50 ms two-tier, seed 20260919, δ=2 s,
# PLOT_N=1024, DRG δ=2. Swept: f in {0,10,20,30,40,50}% (random) + a targeted demo. ONE deliberate
# deviation: UPSTREAM_TTL=0 (A2's cold-path knob) so node 0 never caches and every query exercises
# the DHT — censorship measured un-masked (see the UPSTREAM_TTL note below; default 300 => A1-A6
# byte-identical). e2e success (from client.csv) still shows the fallback recovering the losses.
#
# Usage:
#   bash experiments/run_b3.sh                                   # full: random sweep + targeted
#   B3_F="0 50" B3_RUNS=1 B3_DURATION=20 bash experiments/run_b3.sh   # quick smoke subset
#   B3_TARGETED=0 bash experiments/run_b3.sh                     # random sweep only
#
# Requires: Docker Desktop running (the testbed brings up 32 ring containers + netem).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
B3_DIR="$RESULTS/b3"

# knobs (env-overridable for smoke runs)
F_LEVELS="${B3_F:-0 10 20 30 40 50}"    # adversary fraction f (percent) for the random sweep
N="${B3_N:-32}"
RUNS="${B3_RUNS:-3}"
QPS="${B3_QPS:-10}"                     # measured offered load (unsaturated)
DURATION="${B3_DURATION:-120}"          # measured window (A6/B1-length -> more distinct Zipf chunks)
WARMUP="${B3_WARMUP:-30}"
WARM_QPS="${B3_WARM_QPS:-10}"
SEED="${B3_SEED:-20260919}"
ALPHA="${B3_ALPHA:-1.0}"
SYNC="${B3_SYNC:-3}"                    # settle+flush seconds after load, before snapshotting logs
DNS_PORT="${B3_DNS_PORT:-5300}"
S="${B3_S:-3}"                          # replication factor (frozen)
MODE="${B3_MODE:-drop}"                 # malicious mode under test (B3 = drop / censorship)
# Cold-path (A2's UPSTREAM_TTL knob): 0 => node 0 never retains a result, so EVERY query exercises
# the DHT and the censorship is measured UN-masked by caching (otherwise node 0 fallback-caches a
# censored popular domain once during warm-up and serves it from cache forever, hiding the attack).
# The default 300 keeps A1-A6 byte-identical; B3 pins 0 so raw-DHT success is the clean signal.
UPSTREAM_TTL="${B3_UPSTREAM_TTL:-0}"
TARGETED="${B3_TARGETED:-1}"           # 1 -> also run the targeted (full-replica) censorship demo
TARGET_RUNS="${B3_TARGET_RUNS:-3}"
RINGNET="rpos-ring_ringnet"
IMG="rpos-node:latest"

note() { echo "== [B3] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ] || fail "missing $TESTBED/run_experiment.sh"
[ -f "$TESTBED/query_gen.py" ]      || fail "missing $TESTBED/query_gen.py"
[ -f "$HERE/b3_placement.py" ]      || fail "missing $HERE/b3_placement.py"

mkdir -p "$B3_DIR"
MANIFEST="$B3_DIR/MANIFEST.txt"
: > "$MANIFEST"
{
    echo "# B3 collection manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# N=$N s=$S mode=$MODE upstream_ttl=$UPSTREAM_TTL measured qps=$QPS duration=$DURATION "\
"warmup=$WARMUP@${WARM_QPS}qps seed=$SEED f_levels='$F_LEVELS' runs=$RUNS targeted=$TARGETED "\
"target_runs=$TARGET_RUNS"
} >> "$MANIFEST"

# tear the ring down (compose + netem). Idempotent — safe on a mid-run abort.
teardown_ring() {
    ( cd "$TESTBED" && docker compose -f docker-compose.nodes.yml down -v >/dev/null 2>&1 ) || true
    ( cd "$TESTBED" && NETWORK="$RINGNET" ./netem.sh clear >/dev/null 2>&1 ) || true
}
trap teardown_ring EXIT   # safety net: whatever is up when the script exits gets cleaned up

# max-workers sized so the generator never caps below the ring (A2's clamp: qps × 5 s timeout).
mw_for() { local q="$1" mw=$(( q * 5 )); [ "$mw" -lt 64 ] && mw=64; [ "$mw" -gt 1024 ] && mw=1024; echo "$mw"; }

# drive the measured load against the LIVE ring. Queries enter at the HONEST seed node 0 only
# (--ring-nodes 1, A6/B1 isolation): node 0 resolves honestly and can fall back, so the measured
# effect is the DHT-layer censorship (how often a lookup must fall back, and the latency cost), not
# "we asked a dead node". node 0 still queries all domains (Zipf), so it lands on censored chunks.
run_level() {   # <out-dir> <N> <qps>
    local dest="$1" n="$2" q="$3" mw; mw="$(mw_for "$q")"
    mkdir -p "$dest"
    local j
    for j in $(seq 0 $((n - 1))); do : > "$RESULTS/ring/$j/queries.csv" 2>/dev/null || true; done
    note "measured ${q} qps for ${DURATION}s (max-workers=$mw, --ring-nodes 1 honest entry) -> $dest/client.csv"
    docker run --rm --network "$RINGNET" -v "$REPO_ROOT":/repo -v "$dest":/out -w /repo/testbed \
        "$IMG" \
        python query_gen.py --qps "$q" --duration "$DURATION" --alpha "$ALPHA" --seed "$SEED" \
            --ring-nodes 1 --ring-dns-port "$DNS_PORT" --max-workers "$mw" \
            --output "/out/client.csv"
}

# snapshot this run's ring/<j>/queries.csv (j in 0..N-1) into dest/ WHILE THE RING IS UP. node 0's
# log is the raw-DHT outcome signal (all queries enter there); the rest are kept for completeness.
snapshot_ring() {   # <dest-dir> <N>
    local dest="$1" n="$2" j found=0
    mkdir -p "$dest/ring"
    for j in $(seq 0 $((n - 1))); do
        if [ -f "$RESULTS/ring/$j/queries.csv" ]; then
            cp "$RESULTS/ring/$j/queries.csv" "$dest/ring/${j}_queries.csv"
            found=$((found + 1))
        fi
    done
    echo "  snapshotted $found/$n ring logs (ring still up) -> $dest"
}

# one measured point: bring up N with the given malicious indices (drop mode), warm, measure,
# snapshot, tear down.
run_point() {   # <dest-dir> <malicious-indices>
    local dest="$1" idx="$2"
    # bring up + converge + warm ONCE at WARM_QPS, leave up (--keep-up). The throwaway --duration 1
    # measured run is ignored; the real B3 load is driven below.
    ( cd "$TESTBED" && UPSTREAM_TTL="$UPSTREAM_TTL" ./run_experiment.sh --mode nodes --nodes "$N" \
        --qps "$WARM_QPS" --duration 1 --warmup "$WARMUP" --seed "$SEED" \
        --replication "$S" --malicious-indices "$idx" --malicious-mode "$MODE" --keep-up )
    run_level "$dest" "$N" "$QPS"
    note "settle ${SYNC}s so node logs flush to the host mount, then snapshot"
    sleep "$SYNC"
    snapshot_ring "$dest" "$N"
    note "tearing down the ring"
    teardown_ring
}

# ---- BLOCK 1: random placement, f x runs (placement resampled per run) --------------------------
for f in $F_LEVELS; do
    nmal="$(python3 -c "print(round($f/100*$N))")"
    for r in $(seq 1 "$RUNS"); do
        dest="$B3_DIR/random/f${f}/run${r}"; mkdir -p "$dest"
        pseed=$(( SEED + r ))
        idx="$(python3 "$HERE/b3_placement.py" --n "$N" --s "$S" --n-mal "$nmal" \
                 --placement random --seed "$pseed" --out "$dest/placement.json")"
        note "random f=${f}% (n_mal=$nmal) run=$r/$RUNS — malicious(drop)=[${idx:-none}] (pseed=$pseed)"
        run_point "$dest" "$idx"
        echo "random f=$f n_mal=$nmal run=$r indices='${idx}' -> results/b3/random/f${f}/run${r}/" >> "$MANIFEST"
    done
done

# ---- BLOCK 2: targeted censorship demo (drop on ALL s replicas of one popular chunk) ------------
if [ "$TARGETED" -eq 1 ]; then
    for r in $(seq 1 "$TARGET_RUNS"); do
        dest="$B3_DIR/targeted/run${r}"; mkdir -p "$dest"
        pseed=$(( SEED + 100 + r ))
        idx="$(python3 "$HERE/b3_placement.py" --n "$N" --s "$S" --placement targeted \
                 --seed "$pseed" --out "$dest/placement.json")"
        tgt="$(python3 -c "import json;print(json.load(open('$dest/placement.json'))['target'])")"
        note "targeted run=$r/$TARGET_RUNS — target=$tgt malicious(drop)=[${idx}] (all s replicas)"
        run_point "$dest" "$idx"
        echo "targeted run=$r target=$tgt indices='${idx}' -> results/b3/targeted/run${r}/" >> "$MANIFEST"
    done
fi

note "collection complete — snapshots under $B3_DIR (see MANIFEST.txt)"
note "next: python3 experiments/b3_censorship.py"
