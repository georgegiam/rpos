#!/usr/bin/env bash
# Issue #36 [A5] — Update commit latency / messages-per-update / ledger growth: data collection
# (Phase 6, examiner point (iii), the resolver's WRITE path).
#
# A5 holds the ring FIXED at N=32 (the frozen emulation ceiling, PARAMETERS.md §1) and s=3 (the
# frozen replication factor), brings it up + converges + warms EXACTLY as A3/A4, then drives
# A5_UPDATES real ledger updates through Algorithm 3's two-phase commit and measures each one:
# commit latency, wire messages, and ring-wide ledger growth. This script ONLY collects the raw
# data; the table / plot / sim cross-check are produced by experiments/a5_updates.py.
#
# THE ONE NEW MECHANISM — there is no DNS UPDATE opcode and query_gen is read-only, so updates
# cannot be driven the way queries are. Instead experiments/a5_driver.py runs as a bare RPC CLIENT
# on the ring network (like query_gen is a client container) and calls the inert ``admin_propose``
# RPC that run_ring_node registers (the ``debug_state`` diagnostics pattern). That handler runs
# node/ledger.py::propose_update UNCHANGED and returns the measured latency + wire-RPC count
# (socket_net.rpc_counter). node/chord.py, node/ledger.py and rpos/rpos.py stay byte-identical
# (CLAUDE.md §2 freeze); the admin RPCs are unreachable unless this driver calls them, so A1–A4
# runs are unaffected.
#
# METHODOLOGY — A4's proven bring-up (warm @ 10 qps then act, ring left UP via --keep-up): we
# reuse run_experiment.sh --mode nodes ... --keep-up for the whole ring lifecycle (zones,
# gen_nodes_compose, health-gate, netem apply, warm-up), then run the update driver against the
# live ring. Repeated A5_RUNS times for run-to-run error bars.
#
# Frozen A5 workload (PARAMETERS.md): N=32, s=3 (default REPLICATION/SUCC_LIST_LEN), 30 s warm-up
# @ 10 qps, netem 5/50 ms two-tier, seed 20260919, δ=2 s, PLOT_N=1024, DRG δ=2. A5_UPDATES=50
# distinct domains (Zipf is irrelevant — each update targets a different chunk).
#
# Usage:
#   bash experiments/run_a5.sh                              # 50 updates x 3 runs at N=32
#   A5_UPDATES=5 A5_RUNS=1 bash experiments/run_a5.sh       # quick smoke subset
#
# Requires: Docker Desktop running (brings up 32 ring containers + netem).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
A5_DIR="$RESULTS/a5"

# knobs (env-overridable for smoke runs)
N="${A5_N:-32}"
UPDATES="${A5_UPDATES:-50}"
RUNS="${A5_RUNS:-3}"
PROPOSER="${A5_PROPOSER:-0}"            # node index that proposes the updates
REPLICATION="${A5_REPLICATION:-3}"      # frozen s
WARMUP="${A5_WARMUP:-30}"
WARM_QPS="${A5_WARM_QPS:-10}"           # low, converging warm-up load (A2/A3's lesson)
SEED="${A5_SEED:-20260919}"
INTERVAL_MS="${A5_INTERVAL_MS:-200}"    # spacing between successive updates
TIMEOUT="${A5_TIMEOUT:-15}"             # per-RPC timeout in the driver
SYNC="${A5_SYNC:-3}"                    # settle seconds before teardown
RING_PORT="${A5_RING_PORT:-7000}"
RING_IP_PREFIX="${A5_RING_IP_PREFIX:-172.30.0}"
RING_IP_BASE="${A5_RING_IP_BASE:-10}"
RINGNET="rpos-ring_ringnet"            # matches run_experiment.sh's RINGNET
IMG="rpos-node:latest"

note() { echo "== [A5] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ]   || fail "missing $TESTBED/run_experiment.sh"
[ -f "$HERE/a5_driver.py" ]           || fail "missing $HERE/a5_driver.py"

mkdir -p "$A5_DIR"
MANIFEST="$A5_DIR/MANIFEST.txt"
: > "$MANIFEST"
{
    echo "# A5 collection manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# N=$N s=$REPLICATION updates=$UPDATES warmup=$WARMUP@${WARM_QPS}qps seed=$SEED "\
"proposer=$PROPOSER interval_ms=$INTERVAL_MS runs=$RUNS"
} >> "$MANIFEST"

# tear the ring down (compose + netem). Idempotent — safe on a mid-run abort.
teardown_ring() {
    ( cd "$TESTBED" && docker compose -f docker-compose.nodes.yml down -v >/dev/null 2>&1 ) || true
    ( cd "$TESTBED" && NETWORK="$RINGNET" ./netem.sh clear >/dev/null 2>&1 ) || true
}
trap teardown_ring EXIT   # safety net: whatever is up when the script exits gets cleaned up

# drive UPDATES ledger updates against the LIVE ring (the write-path analogue of run_a4::run_level).
run_updates() {   # <out-dir> <N>
    local dest="$1" n="$2"
    mkdir -p "$dest"
    note "driving $UPDATES updates via node-$PROPOSER (interval ${INTERVAL_MS}ms) -> $dest/updates.csv"
    docker run --rm --network "$RINGNET" -v "$REPO_ROOT":/repo -v "$dest":/out -w /repo \
        "$IMG" \
        python experiments/a5_driver.py --ring-nodes "$n" --updates "$UPDATES" \
            --proposer "$PROPOSER" --replication "$REPLICATION" \
            --ring-ip-prefix "$RING_IP_PREFIX" --ring-ip-base "$RING_IP_BASE" \
            --ring-port "$RING_PORT" --seed "$SEED" --interval-ms "$INTERVAL_MS" \
            --timeout "$TIMEOUT" --manifest /repo/testbed/dns/zones/MANIFEST.json \
            --output /out/updates.csv
}

# ---- resolver ring: RUNS updates-runs at fixed N=32, s=3 ---------------------------------------
for r in $(seq 1 "$RUNS"); do
    dest="$A5_DIR/run${r}"
    note "run=$r/$RUNS — bring up N=$N (s=$REPLICATION) + warm ${WARMUP}s @ ${WARM_QPS} qps, then drive $UPDATES updates"
    # bring up + converge + warm ONCE at the low WARM_QPS, leave the ring up (--keep-up). The
    # throwaway --duration 1 measured query run is ignored; A5 drives updates, not queries.
    ( cd "$TESTBED" && ./run_experiment.sh --mode nodes --nodes "$N" --qps "$WARM_QPS" \
        --duration 1 --warmup "$WARMUP" --seed "$SEED" --keep-up )

    run_updates "$dest" "$N"
    note "settle ${SYNC}s, then tear down the ring"
    sleep "$SYNC"
    teardown_ring
    echo "nodes N=$N s=$REPLICATION updates=$UPDATES run=$r -> results/a5/run${r}/{updates.csv,growth.json}" >> "$MANIFEST"
done

note "collection complete — snapshots under $A5_DIR (see MANIFEST.txt)"
note "next: python3 experiments/a5_updates.py"
