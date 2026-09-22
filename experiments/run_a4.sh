#!/usr/bin/env bash
# Issue #35 [A4] — Replication cost: data collection (Phase 6, examiner point (iii)).
#
# A4 holds the ring FIXED at N=32 (the frozen emulation ceiling, PARAMETERS.md §1) and 10 qps
# (unsaturated — a latency/cost measurement, not a saturation one), and sweeps the REPLICATION
# FACTOR s over {3, 5, 7}, 3 runs each. It measures what higher replication COSTS: end-to-end
# latency, messages per query, and (for completeness) success rate. This script ONLY collects the
# emulation raw data; the table / plot / sim cross-check are produced by
# experiments/a4_replication.py.
#
# THE ONE NON-OBVIOUS KNOB — successor-list length. The replica set is [primary] + up to
# SUCC_LIST_LEN successors, truncated to s (node/storage.py replica_set). node/chord.py caps the
# successor list at SUCC_LIST_LEN=3, so s>4 would silently yield only 4 replicas. A4 therefore
# raises the successor list to max(3, s-1): s=3->3 (== the frozen default, so the s=3 point
# reproduces A1/A3 exactly), s=5->4, s=7->6. This is applied via run_experiment.sh's new
# --succ-list-len flag, which run_ring_node turns into a RUNTIME override of the chord.py module
# global (SUCC_LIST_LEN is read every maintenance round) — node/chord.py source is NOT modified and
# stays byte-identical (CLAUDE.md §2 freeze preserved; default 3 => every other experiment unchanged).
#
# METHODOLOGY — A3's proven bring-up (warm @ 10 qps then measure, snapshot ring logs WHILE UP):
# per-query message load needs the COMPLETE node-side (outcome, hops) record, and Docker's
# bind-mount write-back loses the tail if the ring is torn down first — so we bring the ring up with
# --keep-up and snapshot the node logs while the containers still run, then tear down. (At 10 qps
# the warm/measure split is light, but we keep A3's shape so emulation and sim per-query-message
# points stay directly comparable — a4_replication.py applies the SAME ring_round_trips model.)
#
# So per (s, run): bring up N=32 with REPLICATION=s / SUCC_LIST_LEN=max(3,s-1) + converge + warm
# @ 10 qps ONCE (--keep-up), truncate the node logs to scope them to the measured window, drive the
# measured 10 qps load, snapshot client.csv + each node's queries.csv WHILE UP, then tear down.
# Repeated 3× per s for run-to-run error bars.
#
# New code in a new file (CLAUDE.md §2): touches no protocol code and no frozen artifact. Reuses
# testbed/run_experiment.sh --mode nodes ... --keep-up (bring-up: zones, gen_nodes_compose,
# health-gate, netem apply, warm-up) and testbed/query_gen.py (the measured load), as run_a3.sh does.
#
# Frozen A4 workload (PARAMETERS.md): N=32, measured 10 qps, 30 s measured, 30 s warm-up @ 10 qps,
# Zipf alpha=1.0 over 1000 Tranco domains, netem 5/50 ms two-tier, seed 20260919, δ=2 s,
# PLOT_N=1024, DRG δ=2. Swept: s in {3,5,7} (SUCC_LIST_LEN=max(3,s-1)).
#
# Usage:
#   bash experiments/run_a4.sh                          # full matrix: s in {3,5,7} x 3 runs
#   A4_S="3" A4_RUNS=1 bash experiments/run_a4.sh       # quick smoke subset
#
# Requires: Docker Desktop running (the testbed brings up 32 ring containers + netem).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
A4_DIR="$RESULTS/a4"

# knobs (env-overridable for smoke runs)
S_LEVELS="${A4_S:-3 5 7}"
N="${A4_N:-32}"
RUNS="${A4_RUNS:-3}"
QPS="${A4_QPS:-10}"                     # measured offered load (unsaturated — a cost/latency exp)
DURATION="${A4_DURATION:-30}"
WARMUP="${A4_WARMUP:-30}"
WARM_QPS="${A4_WARM_QPS:-10}"           # low, converging warm-up load (A2/A3's lesson)
SEED="${A4_SEED:-20260919}"
ALPHA="${A4_ALPHA:-1.0}"
SYNC="${A4_SYNC:-3}"                    # settle+flush seconds after load, before snapshotting logs
DNS_PORT="${A4_DNS_PORT:-5300}"
RINGNET="rpos-ring_ringnet"            # matches run_experiment.sh's RINGNET (ring_load network)
IMG="rpos-node:latest"

note() { echo "== [A4] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ] || fail "missing $TESTBED/run_experiment.sh"
[ -f "$TESTBED/query_gen.py" ]      || fail "missing $TESTBED/query_gen.py"

mkdir -p "$A4_DIR"
MANIFEST="$A4_DIR/MANIFEST.txt"
: > "$MANIFEST"
{
    echo "# A4 collection manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# N=$N measured qps=$QPS duration=$DURATION warmup=$WARMUP@${WARM_QPS}qps seed=$SEED "\
"s_levels='$S_LEVELS' runs=$RUNS"
} >> "$MANIFEST"

# successor-list length a replica set of s needs: [primary] + (s-1) successors. s=3 keeps the
# frozen default 3 (so the s=3 point == A1/A3); s=5->4, s=7->6.
sll_for() { local s="$1"; local l=$(( s - 1 )); [ "$l" -lt 3 ] && l=3; echo "$l"; }

# tear the ring down (compose + netem). Idempotent — safe on a mid-run abort.
teardown_ring() {
    ( cd "$TESTBED" && docker compose -f docker-compose.nodes.yml down -v >/dev/null 2>&1 ) || true
    ( cd "$TESTBED" && NETWORK="$RINGNET" ./netem.sh clear >/dev/null 2>&1 ) || true
}
trap teardown_ring EXIT   # safety net: whatever is up when the script exits gets cleaned up

# max-workers sized so the generator never caps below the ring (A2's clamp: qps × 5 s timeout).
mw_for() { local q="$1" mw=$(( q * 5 )); [ "$mw" -lt 64 ] && mw=64; [ "$mw" -gt 1024 ] && mw=1024; echo "$mw"; }

# drive the measured load against the LIVE ring (mirrors run_a3.sh's run_level).
run_level() {   # <out-dir> <N> <qps>
    local dest="$1" n="$2" q="$3" mw; mw="$(mw_for "$q")"
    mkdir -p "$dest"
    local j
    for j in $(seq 0 $((n - 1))); do : > "$RESULTS/ring/$j/queries.csv" 2>/dev/null || true; done
    note "measured ${q} qps for ${DURATION}s (max-workers=$mw) -> $dest/client.csv"
    docker run --rm --network "$RINGNET" -v "$REPO_ROOT":/repo -v "$dest":/out -w /repo/testbed \
        "$IMG" \
        python query_gen.py --qps "$q" --duration "$DURATION" --alpha "$ALPHA" --seed "$SEED" \
            --ring-nodes "$n" --ring-dns-port "$DNS_PORT" --max-workers "$mw" \
            --output "/out/client.csv"
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

# ---- resolver ring: s x runs at fixed N=32 and the A4 offered load -----------------------------
for s in $S_LEVELS; do
    sll="$(sll_for "$s")"
    for r in $(seq 1 "$RUNS"); do
        dest="$A4_DIR/s${s}/run${r}"
        note "s=$s (succ-list-len=$sll) run=$r/$RUNS — bring up N=$N + warm ${WARMUP}s @ ${WARM_QPS} qps, then measure @ ${QPS} qps"
        # bring up + converge + warm ONCE at the low WARM_QPS, leave the ring up (--keep-up). The
        # throwaway --duration 1 measured run is ignored; the real A4 load is driven below.
        ( cd "$TESTBED" && ./run_experiment.sh --mode nodes --nodes "$N" --qps "$WARM_QPS" \
            --duration 1 --warmup "$WARMUP" --seed "$SEED" \
            --replication "$s" --succ-list-len "$sll" --keep-up )

        run_level "$dest" "$N" "$QPS"
        note "settle ${SYNC}s so the node logs flush to the host mount, then snapshot"
        sleep "$SYNC"
        snapshot_ring "$dest" "$N"

        note "s=$s run=$r complete — tearing down the ring"
        teardown_ring
        echo "nodes s=$s sll=$sll N=$N run=$r -> results/a4/s${s}/run${r}/{client.csv,ring/}" >> "$MANIFEST"
    done
done

note "collection complete — snapshots under $A4_DIR (see MANIFEST.txt)"
note "next: python3 experiments/a4_replication.py"
