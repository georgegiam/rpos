#!/usr/bin/env bash
# Issue #45 [B4] — Routing / eclipse: OPTIONAL socket cross-check (Phase 7, examiner point (ii)).
#
# THE PRIMARY B4 DELIVERABLE IS experiments/b4_inproc.py (real in-process ring → results/B4_eclipse.csv):
# unlike B3's `drop`, `misroute` does NOT stall the in-process transport, so the in-process run is the
# MOST faithful vehicle (real resolve_query, real hops/outcomes). This script is an OPTIONAL, flagged
# socket-testbed anchor for realistic-network latency only; it writes a SEPARATE file
# (results/B4_eclipse_socket.csv) so a slow/flaky testbed run NEVER clobbers the primary.
#
# WHAT IT DOES: holds the ring at N=32, s=3, 10 qps and makes a fraction f of nodes MALICIOUS with
# MALICIOUS_MODE=misroute (node/malicious.py's _h_find_successor/_h_closest_preceding: claim
# successor-of-everything, bounce the querier back to self). Queries enter the HONEST seed node 0
# (--ring-nodes 1) so a poisoned lookup is attributable to the ring, not the entry node. node 0's
# queries.csv (hops, outcome) is the raw-DHT/eclipse + extra-hop signal; client.csv is e2e + latency.
#
# OPERATIONAL RISK (flagged, CLAUDE.md §2): a misrouting ring can perturb chord.py maintenance under
# load (N=64 residual wall, Phase 3) and the nodes-mode health gate probes a lookup through node 0 —
# but a misrouted probe FALLS BACK and still returns a valid A, and run_experiment.sh already relaxes
# the gate to any-valid-A when --malicious-indices is set, so bring-up usually passes. Default here is
# a LIGHT anchor (f in {0,10}, 1 run); widen via env only if the ring is stable.
#
# NO FROZEN EDIT: reuses run_experiment.sh's --malicious-indices + --malicious-mode (added for B1/B3);
# placement from experiments/b4_placement.py. node/* and rpos/rpos.py are untouched (misroute exists).
# UPSTREAM_TTL=0 (A2's cold-path knob) so node 0 never caches and every query exercises the routing.
#
# Usage:
#   bash experiments/run_b4.sh                                  # light anchor: f={0,10}, 1 run
#   B4_F="0 10 20 30 40 50" B4_RUNS=3 bash experiments/run_b4.sh # full sweep (if the ring is stable)
#   B4_TARGETED=1 bash experiments/run_b4.sh                    # also the victim-node eclipse demo
# Then: python3 experiments/b4_eclipse.py
#
# Requires: Docker Desktop running (brings up 32 ring containers + netem).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
B4_DIR="$RESULTS/b4"

F_LEVELS="${B4_F:-0 10}"                 # light anchor by default (primary is b4_inproc)
N="${B4_N:-32}"
RUNS="${B4_RUNS:-1}"
QPS="${B4_QPS:-10}"
DURATION="${B4_DURATION:-120}"
WARMUP="${B4_WARMUP:-30}"
WARM_QPS="${B4_WARM_QPS:-10}"
SEED="${B4_SEED:-20260919}"
ALPHA="${B4_ALPHA:-1.0}"
SYNC="${B4_SYNC:-3}"
DNS_PORT="${B4_DNS_PORT:-5300}"
S="${B4_S:-3}"
MODE="${B4_MODE:-misroute}"              # malicious mode under test (B4 = misroute / eclipse)
UPSTREAM_TTL="${B4_UPSTREAM_TTL:-0}"     # cold path so caching never masks a poisoned lookup
TARGETED="${B4_TARGETED:-0}"            # 1 -> also run the victim-node eclipse demo (one misrouter)
TARGET_RUNS="${B4_TARGET_RUNS:-3}"
RINGNET="rpos-ring_ringnet"
IMG="rpos-node:latest"

note() { echo "== [B4] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ] || fail "missing $TESTBED/run_experiment.sh"
[ -f "$TESTBED/query_gen.py" ]      || fail "missing $TESTBED/query_gen.py"
[ -f "$HERE/b4_placement.py" ]      || fail "missing $HERE/b4_placement.py"

mkdir -p "$B4_DIR"
MANIFEST="$B4_DIR/MANIFEST.txt"
: > "$MANIFEST"
{
    echo "# B4 collection manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# N=$N s=$S mode=$MODE upstream_ttl=$UPSTREAM_TTL measured qps=$QPS duration=$DURATION "\
"warmup=$WARMUP@${WARM_QPS}qps seed=$SEED f_levels='$F_LEVELS' runs=$RUNS targeted=$TARGETED"
} >> "$MANIFEST"

teardown_ring() {
    ( cd "$TESTBED" && docker compose -f docker-compose.nodes.yml down -v >/dev/null 2>&1 ) || true
    ( cd "$TESTBED" && NETWORK="$RINGNET" ./netem.sh clear >/dev/null 2>&1 ) || true
}
trap teardown_ring EXIT

mw_for() { local q="$1" mw=$(( q * 5 )); [ "$mw" -lt 64 ] && mw=64; [ "$mw" -gt 1024 ] && mw=1024; echo "$mw"; }

# drive the measured load against the LIVE ring — queries enter the HONEST seed node 0 only.
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

run_point() {   # <dest-dir> <malicious-indices>
    local dest="$1" idx="$2"
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
        dest="$B4_DIR/random/f${f}/run${r}"; mkdir -p "$dest"
        pseed=$(( SEED + r ))
        idx="$(python3 "$HERE/b4_placement.py" --n "$N" --s "$S" --n-mal "$nmal" \
                 --placement random --seed "$pseed" --out "$dest/placement.json")"
        note "random f=${f}% (n_mal=$nmal) run=$r/$RUNS — malicious(misroute)=[${idx:-none}] (pseed=$pseed)"
        run_point "$dest" "$idx"
        echo "random f=$f n_mal=$nmal run=$r indices='${idx}' -> results/b4/random/f${f}/run${r}/" >> "$MANIFEST"
    done
done

# ---- BLOCK 2: targeted victim-node eclipse (one misrouter on the victim's on-path hop) ----------
if [ "$TARGETED" -eq 1 ]; then
    for r in $(seq 1 "$TARGET_RUNS"); do
        dest="$B4_DIR/targeted/run${r}"; mkdir -p "$dest"
        pseed=$(( SEED + 100 + r ))
        idx="$(python3 "$HERE/b4_placement.py" --n "$N" --s "$S" --placement targeted \
                 --seed "$pseed" --out "$dest/placement.json")"
        vic="$(python3 -c "import json;print(json.load(open('$dest/placement.json')).get('victim_idx'))")"
        note "targeted run=$r/$TARGET_RUNS — victim_idx=$vic malicious(misroute)=[${idx}] (one on-path hop)"
        run_point "$dest" "$idx"
        echo "targeted run=$r victim_idx=$vic indices='${idx}' -> results/b4/targeted/run${r}/" >> "$MANIFEST"
    done
fi

note "collection complete — snapshots under $B4_DIR (see MANIFEST.txt)"
note "next: python3 experiments/b4_eclipse.py"
