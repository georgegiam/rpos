#!/usr/bin/env bash
# Issue #42 [B1] — Tampering / cache poisoning: data collection (Phase 7, examiner point (ii)).
#
# B1 holds the ring FIXED at N=32 (frozen emulation ceiling, PARAMETERS.md §1), s=3, 10 qps, and
# makes a fraction f of the nodes MALICIOUS (MALICIOUS_MODE=lie -> node/malicious.py returns the
# forged A-record 6.6.6.6). It measures how often clients ACCEPT a forged answer, swept over f,
# against the majority-vote bound (a chunk is captured only when >= ceil((s+1)/2)=2 of its 3
# replicas lie). This script ONLY collects raw data; the table / plot / bound overlay are produced
# by experiments/b1_tampering.py.
#
# TWO PLACEMENT BLOCKS:
#   random   — f in {0,10,20,30,40,50}% -> n_mal = round(f*32) = {0,3,6,10,13,16} chosen uniformly
#              from indices 1..31 (node 0, the seed/entry anchor, stays honest). Placement is
#              RESAMPLED per run (seed = SEED+run) so the 3 runs are independent samples of the
#              bound. f=0 is the HONEST CONTROL (epic cross-cutting requirement).
#   targeted — co-locate the minimum capturing budget (2 nodes) on ONE popular chunk's replica set,
#              so that chunk is forged regardless of the global f (the colluding case that CROSSES
#              the bound). 3 runs. (Feasibility of achieving such placement by id-grinding is B2.)
#
# THE NEW DRIVER (no frozen edit, CLAUDE.md §2): experiments/b1_placement.py computes WHICH node
# indices are malicious (host-side, reproducible from (N,s,seed)); gen_nodes_compose.py's new
# --malicious-indices (threaded via run_experiment.sh) makes exactly those nodes run lie; the rest
# default honest, so with no indices every other experiment is byte-identical. query_gen.py's new
# --check-answers compares each reply's A record to the ground-truth answer_ip and logs forgery.
# node/* and rpos/rpos.py are untouched (the lie behaviour + majority vote already exist).
#
# METHODOLOGY — A4/A6's proven bring-up (warm @ 10 qps, measure, snapshot ring logs WHILE UP):
# per (block, point, run) bring up N=32 with the computed --malicious-indices, converge + warm @
# 10 qps ONCE (--keep-up), truncate node logs to scope the window, drive the measured load with
# --ring-nodes 32 --check-answers (so queries enter the WHOLE ring and can land on captured
# chunks), snapshot client.csv + each node's queries.csv while up, then tear down.
#
# Frozen B1 workload (PARAMETERS.md): N=32, s=3, measured 10 qps, 120 s measured, 30 s warm-up @
# 10 qps, Zipf alpha=1.0 over 1000 Tranco domains, netem 5/50 ms two-tier, seed 20260919, δ=2 s,
# PLOT_N=1024, DRG δ=2. Swept: f in {0,10,20,30,40,50}% (random) + a targeted demo.
#
# Usage:
#   bash experiments/run_b1.sh                                   # full: random sweep + targeted
#   B1_F="0 50" B1_RUNS=1 B1_DURATION=20 bash experiments/run_b1.sh   # quick smoke subset
#   B1_TARGETED=0 bash experiments/run_b1.sh                     # random sweep only
#
# Requires: Docker Desktop running (the testbed brings up 32 ring containers + netem).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
B1_DIR="$RESULTS/b1"

# knobs (env-overridable for smoke runs)
F_LEVELS="${B1_F:-0 10 20 30 40 50}"    # adversary fraction f (percent) for the random sweep
N="${B1_N:-32}"
RUNS="${B1_RUNS:-3}"
QPS="${B1_QPS:-10}"                     # measured offered load (unsaturated)
DURATION="${B1_DURATION:-120}"          # measured window (A6-length -> more distinct Zipf chunks)
WARMUP="${B1_WARMUP:-30}"
WARM_QPS="${B1_WARM_QPS:-10}"
SEED="${B1_SEED:-20260919}"
ALPHA="${B1_ALPHA:-1.0}"
SYNC="${B1_SYNC:-3}"                    # settle+flush seconds after load, before snapshotting logs
DNS_PORT="${B1_DNS_PORT:-5300}"
S="${B1_S:-3}"                          # replication factor (frozen)
TARGETED="${B1_TARGETED:-1}"           # 1 -> also run the targeted/colluding demo block
TARGET_RUNS="${B1_TARGET_RUNS:-3}"
TARGET_BUDGET="${B1_TARGET_BUDGET:-2}" # minimum capturing budget at s=3 (ceil((s+1)/2))
RINGNET="rpos-ring_ringnet"
IMG="rpos-node:latest"

note() { echo "== [B1] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ] || fail "missing $TESTBED/run_experiment.sh"
[ -f "$TESTBED/query_gen.py" ]      || fail "missing $TESTBED/query_gen.py"
[ -f "$HERE/b1_placement.py" ]      || fail "missing $HERE/b1_placement.py"

mkdir -p "$B1_DIR"
MANIFEST="$B1_DIR/MANIFEST.txt"
: > "$MANIFEST"
{
    echo "# B1 collection manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# N=$N s=$S measured qps=$QPS duration=$DURATION warmup=$WARMUP@${WARM_QPS}qps seed=$SEED "\
"f_levels='$F_LEVELS' runs=$RUNS targeted=$TARGETED target_runs=$TARGET_RUNS budget=$TARGET_BUDGET"
} >> "$MANIFEST"

# tear the ring down (compose + netem). Idempotent — safe on a mid-run abort.
teardown_ring() {
    ( cd "$TESTBED" && docker compose -f docker-compose.nodes.yml down -v >/dev/null 2>&1 ) || true
    ( cd "$TESTBED" && NETWORK="$RINGNET" ./netem.sh clear >/dev/null 2>&1 ) || true
}
trap teardown_ring EXIT   # safety net: whatever is up when the script exits gets cleaned up

# max-workers sized so the generator never caps below the ring (A2's clamp: qps × 5 s timeout).
mw_for() { local q="$1" mw=$(( q * 5 )); [ "$mw" -lt 64 ] && mw=64; [ "$mw" -gt 1024 ] && mw=1024; echo "$mw"; }

# drive the measured load against the LIVE ring with forgery detection (--check-answers).
# Queries enter at the HONEST seed node 0 only (--ring-nodes 1, A6's isolation pattern): node 0
# resolves honestly, so any forgery comes purely from the DHT replica vote — isolating the
# majority-vote defence against the bound. node 0 still queries all domains (Zipf), so it lands on
# captured chunks. (Entering at all 32 nodes would conflate entry-node selection with the vote.)
run_level() {   # <out-dir> <N> <qps>
    local dest="$1" n="$2" q="$3" mw; mw="$(mw_for "$q")"
    mkdir -p "$dest"
    local j
    for j in $(seq 0 $((n - 1))); do : > "$RESULTS/ring/$j/queries.csv" 2>/dev/null || true; done
    note "measured ${q} qps for ${DURATION}s (max-workers=$mw, --ring-nodes 1 honest entry, --check-answers) -> $dest/client.csv"
    docker run --rm --network "$RINGNET" -v "$REPO_ROOT":/repo -v "$dest":/out -w /repo/testbed \
        "$IMG" \
        python query_gen.py --qps "$q" --duration "$DURATION" --alpha "$ALPHA" --seed "$SEED" \
            --ring-nodes 1 --ring-dns-port "$DNS_PORT" --max-workers "$mw" \
            --check-answers --output "/out/client.csv"
}

# snapshot this run's ring/<j>/queries.csv (j in 0..N-1) into dest/ WHILE THE RING IS UP.
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

# one measured point: bring up N with the given malicious indices, warm, measure, snapshot, tear down.
run_point() {   # <dest-dir> <malicious-indices>
    local dest="$1" idx="$2"
    # bring up + converge + warm ONCE at WARM_QPS, leave up (--keep-up). The throwaway --duration 1
    # measured run is ignored; the real B1 load is driven below.
    ( cd "$TESTBED" && ./run_experiment.sh --mode nodes --nodes "$N" --qps "$WARM_QPS" \
        --duration 1 --warmup "$WARMUP" --seed "$SEED" \
        --replication "$S" --malicious-indices "$idx" --keep-up )
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
        dest="$B1_DIR/random/f${f}/run${r}"; mkdir -p "$dest"
        pseed=$(( SEED + r ))
        idx="$(python3 "$HERE/b1_placement.py" --n "$N" --s "$S" --n-mal "$nmal" \
                 --placement random --seed "$pseed" --out "$dest/placement.json")"
        note "random f=${f}% (n_mal=$nmal) run=$r/$RUNS — malicious=[${idx:-none}] (pseed=$pseed)"
        run_point "$dest" "$idx"
        echo "random f=$f n_mal=$nmal run=$r indices='${idx}' -> results/b1/random/f${f}/run${r}/" >> "$MANIFEST"
    done
done

# ---- BLOCK 2: targeted / colluding demo (minimum budget on one popular chunk) -------------------
if [ "$TARGETED" -eq 1 ]; then
    for r in $(seq 1 "$TARGET_RUNS"); do
        dest="$B1_DIR/targeted/run${r}"; mkdir -p "$dest"
        pseed=$(( SEED + 100 + r ))
        idx="$(python3 "$HERE/b1_placement.py" --n "$N" --s "$S" --placement targeted \
                 --budget "$TARGET_BUDGET" --seed "$pseed" --out "$dest/placement.json")"
        tgt="$(python3 -c "import json;print(json.load(open('$dest/placement.json'))['target'])")"
        note "targeted run=$r/$TARGET_RUNS — target=$tgt malicious=[${idx}] budget=$TARGET_BUDGET"
        run_point "$dest" "$idx"
        echo "targeted run=$r target=$tgt indices='${idx}' -> results/b1/targeted/run${r}/" >> "$MANIFEST"
    done
fi

note "collection complete — snapshots under $B1_DIR (see MANIFEST.txt)"
note "next: python3 experiments/b1_tampering.py"
