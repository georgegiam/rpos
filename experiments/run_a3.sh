#!/usr/bin/env bash
# Issue #34 [A3] — Scalability (throughput & per-node load vs N): data collection (Phase 6,
# examiner point (iii): scalability of the whole resolver).
#
# A3 holds the offered load FIXED at 50 qps and sweeps the ring size N over {4, 8, 16, 32} (the
# frozen N=32 emulation ceiling, PARAMETERS.md §1), 3 runs each, to show how throughput and
# per-node message load behave as the ring grows. The large-N points (1,000 / 5,000 / 10,000)
# come from the calibrated Phase-5 simulator, re-run at 50 qps by experiments/a3_scalability.py so
# the whole curve sits at one offered load. This script ONLY collects the emulation raw data; the
# combine / table / plot are produced by experiments/a3_scalability.py.
#
# METHODOLOGY — A2's proven bring-up (NOT A1's one-shot), for two reasons A3 uniquely needs:
#
#   1. Per-node load needs the COMPLETE node-side (outcome, hops) record. A1's pattern runs
#      run_experiment.sh WITHOUT --keep-up (it tears the ring down internally) and snapshots the
#      ring logs AFTERWARDS — but Docker Desktop's bind-mount write-back loses the last writes when
#      the containers are killed, so the node logs come back short of the client query count. A1
#      only used those logs for RELATIVE outcome shares (uniform loss is harmless there); A3 needs
#      ABSOLUTE message counts, so we bring the ring up with --keep-up and SNAPSHOT THE RING LOGS
#      WHILE THE CONTAINERS ARE STILL RUNNING (they are written live to the host mount — that is
#      what run_experiment.sh's hop-count summary reads), then tear down.
#
#   2. N=32 convergence. Warming a FRESH 32-node ring at the measured 50 qps perturbs stabilize
#      before it converges (a milder N=64 failure mode, CLAUDE.md Phase 3) — success collapses.
#      A2 showed that warming at a low 10 qps and THEN driving 50 qps holds ~97% at N=32. A3 does
#      the same: warm at WARM_QPS=10, then run the measured load at 50 qps.
#
# So per (N, run): bring up + converge + warm @ 10 qps ONCE (--keep-up), truncate the node logs to
# scope them to the measured window, drive the measured 50 qps load, snapshot client.csv + each
# node's queries.csv WHILE UP, then tear down. Repeated 3× per N for run-to-run error bars.
#
# It is new code in a new file (CLAUDE.md §2): it touches no protocol code and no frozen artifact.
# It reuses testbed/run_experiment.sh --mode nodes ... --keep-up (bring-up: zones,
# gen_nodes_compose, health-gate, netem apply, warm-up) and testbed/query_gen.py (the measured
# load), exactly as run_a2.sh does.
#
# A3 needs BOTH log halves: the client CSV gives throughput/goodput/success, and the per-node ring
# logs give per-node message load (a3_scalability.py applies the sim's ring_round_trips message
# model to each node's (outcome, hops) rows — the same model the simulator uses, so the emulation
# and sim per-node-load points are directly comparable).
#
# No Unbound baseline: per-node load is a property of the decentralised ring; Unbound is a single
# centralised resolver, so a per-node-load-vs-N curve does not apply to it.
#
# Frozen A3 workload (PARAMETERS.md): measured 50 qps, 30 s measured, 30 s warm-up @ 10 qps, Zipf
# alpha=1.0 over 1000 Tranco domains, netem 5/50 ms two-tier, seed 20260919, s=3, δ=2 s,
# PLOT_N=1024, DRG δ=2.
#
# Usage:
#   bash experiments/run_a3.sh                          # full matrix: N in {4,8,16,32} x 3
#   A3_NS="8 32" A3_RUNS=1 bash experiments/run_a3.sh   # quick smoke subset
#
# Requires: Docker Desktop running (the testbed brings up N ring containers + netem).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
A3_DIR="$RESULTS/a3"

# knobs (env-overridable for smoke runs)
NS="${A3_NS:-4 8 16 32}"
RUNS="${A3_RUNS:-3}"
QPS="${A3_QPS:-50}"                     # measured offered load (the A3 fixed load)
DURATION="${A3_DURATION:-30}"
WARMUP="${A3_WARMUP:-30}"
WARM_QPS="${A3_WARM_QPS:-10}"           # low, converging warm-up load (A2's lesson; not saturating)
SEED="${A3_SEED:-20260919}"
ALPHA="${A3_ALPHA:-1.0}"
SYNC="${A3_SYNC:-3}"                    # settle+flush seconds after load, before snapshotting logs
DNS_PORT="${A3_DNS_PORT:-5300}"
RINGNET="rpos-ring_ringnet"            # matches run_experiment.sh's RINGNET (ring_load network)
IMG="rpos-node:latest"

note() { echo "== [A3] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ] || fail "missing $TESTBED/run_experiment.sh"
[ -f "$TESTBED/query_gen.py" ]      || fail "missing $TESTBED/query_gen.py"

mkdir -p "$A3_DIR"
MANIFEST="$A3_DIR/MANIFEST.txt"
: > "$MANIFEST"
{
    echo "# A3 collection manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# measured qps=$QPS duration=$DURATION warmup=$WARMUP@${WARM_QPS}qps seed=$SEED "\
"ns='$NS' runs=$RUNS"
} >> "$MANIFEST"

# tear the ring down (compose + netem). Idempotent — safe on a mid-run abort.
teardown_ring() {
    ( cd "$TESTBED" && docker compose -f docker-compose.nodes.yml down -v >/dev/null 2>&1 ) || true
    ( cd "$TESTBED" && NETWORK="$RINGNET" ./netem.sh clear >/dev/null 2>&1 ) || true
}
trap teardown_ring EXIT   # safety net: whatever is up when the script exits gets cleaned up

# max-workers sized so the generator never caps below the ring (A2's clamp: qps × 5 s timeout).
mw_for() { local q="$1" mw=$(( q * 5 )); [ "$mw" -lt 64 ] && mw=64; [ "$mw" -gt 1024 ] && mw=1024; echo "$mw"; }

# drive the measured load against the LIVE ring (mirrors run_a2.sh's run_level).
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

# ---- resolver ring: N x runs at the fixed A3 offered load -----------------------------------
for N in $NS; do
    for r in $(seq 1 "$RUNS"); do
        dest="$A3_DIR/N${N}/run${r}"
        note "N=$N run=$r/$RUNS — bring up + warm ${WARMUP}s @ ${WARM_QPS} qps, then measure @ ${QPS} qps"
        # bring up + converge + warm ONCE at the low WARM_QPS, leave the ring up (--keep-up). The
        # throwaway --duration 1 measured run is ignored; the real A3 load is driven below.
        ( cd "$TESTBED" && ./run_experiment.sh --mode nodes --nodes "$N" --qps "$WARM_QPS" \
            --duration 1 --warmup "$WARMUP" --seed "$SEED" --keep-up )

        run_level "$dest" "$N" "$QPS"
        note "settle ${SYNC}s so the node logs flush to the host mount, then snapshot"
        sleep "$SYNC"
        snapshot_ring "$dest" "$N"

        note "N=$N run=$r complete — tearing down the ring"
        teardown_ring
        echo "nodes N=$N run=$r -> results/a3/N${N}/run${r}/{client.csv,ring/}" >> "$MANIFEST"
    done
done

note "collection complete — snapshots under $A3_DIR (see MANIFEST.txt)"
note "next: python3 experiments/a3_scalability.py"
