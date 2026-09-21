#!/usr/bin/env bash
# Issue #33 [A2] — Throughput / saturation: data collection (Phase 6, examiner point (iii)).
#
# A2 measures how the resolver ring's success rate and p95 latency degrade as offered query
# load rises, and locates the saturation point (first load level with success < 95%). It fixes
# the ring at the frozen N=32 emulation ceiling (PARAMETERS.md §1) and ramps the offered rate
# over {10, 25, 50, 100, 150, 200} qps, 30 s per level.
#
# Methodology (decided): ONE ring per sweep, ramp load on it (the standard saturation method) —
# NOT a fresh ring per level. We bring the ring up once, warm it at a low fixed 10 qps until it
# converges + populates the DHT, then run all 6 levels ascending against the SAME live ring,
# with a short drain between levels so a saturated level's backlog clears before the next. This
# avoids warming an unconverged ring at a high qps, which would starve stabilize (the N=64
# failure mode, CLAUDE.md Phase 3) and confound a throughput measurement with convergence.
# The whole 6-level sweep is repeated 3× on independent bring-ups for run-to-run error bars
# (A1's 3-run convention / Phase 6's "3–5×" rule).
#
# This script ONLY collects raw data; the table / saturation marker / plot are produced by
# experiments/a2_throughput.py. It is new code in a new file (CLAUDE.md §2): it touches no
# protocol code and no frozen artifact. It reuses:
#   * testbed/run_experiment.sh --mode nodes ... --keep-up   -> full ring bring-up (zones,
#     gen_nodes_compose, health-gate, netem apply, 30 s warm-up), left running afterwards.
#   * testbed/query_gen.py (unmodified) run directly against the live ring for each load level.
#
# The generator cap (flagged, not hidden — PARAMETERS.md §3): query_gen.py is open-loop but
# bounded by its worker pool (default 64). Above ~64 concurrent queries the GENERATOR, not the
# ring, would be the bottleneck. A2's higher levels exceed that, so each direct load passes
# --max-workers = clamp(qps × 5 s timeout, 64, 1024) so the RING saturates first. a2_throughput.py
# records achieved_qps = rows/duration per level as the diagnostic: achieved << offered while
# success stays high => a residual generator cap; success < 95% => true ring saturation.
#
# Frozen A2 workload (PARAMETERS.md): N=32, 30 s measured per level, 30 s warm-up at 10 qps,
# Zipf alpha=1.0 over 1000 Tranco domains, netem 5/50 ms two-tier, seed 20260919, s=3, δ=2 s,
# PLOT_N=1024, DRG in-degree 2.
#
# Usage:
#   bash experiments/run_a2.sh                                  # 3 sweeps × 6 levels on N=32
#   A2_QPS="10 50" A2_SWEEPS=1 bash experiments/run_a2.sh       # quick smoke subset
#   A2_SWEEPS=1 bash experiments/run_a2.sh                      # single sweep (no error bars)
#
# Requires: Docker Desktop running (brings up the N=32 ring + netem).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
A2_DIR="$RESULTS/a2"

# knobs (env-overridable for smoke runs)
QPS_LEVELS="${A2_QPS:-10 25 50 100 150 200}"
SWEEPS="${A2_SWEEPS:-3}"
N="${A2_N:-32}"
DURATION="${A2_DURATION:-30}"
WARMUP="${A2_WARMUP:-30}"
WARM_QPS="${A2_WARM_QPS:-10}"          # low, converging warm-up load (not a saturating one)
SEED="${A2_SEED:-20260919}"
ALPHA="${A2_ALPHA:-1.0}"
DRAIN="${A2_DRAIN:-5}"                  # inter-level settle (seconds) so a backlog drains
DNS_PORT="${A2_DNS_PORT:-5300}"
RINGNET="rpos-ring_ringnet"            # matches run_experiment.sh's RINGNET (ring_load network)
IMG="rpos-node:latest"

note() { echo "== [A2] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ] || fail "missing $TESTBED/run_experiment.sh"
[ -f "$TESTBED/query_gen.py" ]      || fail "missing $TESTBED/query_gen.py"

mkdir -p "$A2_DIR"
MANIFEST="$A2_DIR/MANIFEST.txt"
: > "$MANIFEST"
{
    echo "# A2 collection manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# N=$N levels='$QPS_LEVELS' duration=$DURATION warmup=$WARMUP@${WARM_QPS}qps "\
"sweeps=$SWEEPS seed=$SEED drain=${DRAIN}s"
} >> "$MANIFEST"

# tear the ring down (compose + netem). Idempotent — safe to call twice / on a mid-sweep abort.
teardown_ring() {
    ( cd "$TESTBED" && docker compose -f docker-compose.nodes.yml down -v >/dev/null 2>&1 ) || true
    ( cd "$TESTBED" && NETWORK="$RINGNET" ./netem.sh clear >/dev/null 2>&1 ) || true
}
# safety net: whatever's up when the script exits (incl. an error mid-sweep) gets cleaned up.
trap teardown_ring EXIT

# clamp helper: max-workers sized so the generator never caps below the ring (see header).
mw_for() {   # <qps>
    local q="$1" mw=$(( q * 5 ))          # qps × 5 s per-query timeout = worst-case in-flight
    [ "$mw" -lt 64 ] && mw=64
    [ "$mw" -gt 1024 ] && mw=1024
    echo "$mw"
}

# one load level against the LIVE ring (mirrors run_experiment.sh's ring_load docker invocation,
# adding --max-workers). Writes client.csv straight into the snapshot dir mounted at /out.
run_level() {   # <snapshot-dir> <qps>
    local dest="$1" q="$2" mw; mw="$(mw_for "$q")"
    mkdir -p "$dest"
    # scope this level's node-side hop logs to the measured window (as run_experiment.sh does)
    local j
    for j in $(seq 0 $((N - 1))); do
        : > "$RESULTS/ring/$j/queries.csv" 2>/dev/null || true
    done
    note "level ${q} qps for ${DURATION}s (max-workers=$mw) -> $dest/client.csv"
    docker run --rm --network "$RINGNET" -v "$REPO_ROOT":/repo -v "$dest":/out -w /repo/testbed \
        "$IMG" \
        python query_gen.py --qps "$q" --duration "$DURATION" --alpha "$ALPHA" --seed "$SEED" \
            --ring-nodes "$N" --ring-dns-port "$DNS_PORT" --max-workers "$mw" \
            --output "/out/client.csv"
}

for s in $(seq 1 "$SWEEPS"); do
    note "sweep $s/$SWEEPS — bringing up + warming N=$N (warm ${WARMUP}s @ ${WARM_QPS} qps)"
    # bring up + converge + warm ONCE, then leave the ring (and netem) running (--keep-up).
    # the tiny --duration 1 measured run is a throwaway; all 6 A2 levels are driven below.
    ( cd "$TESTBED" && ./run_experiment.sh --mode nodes --nodes "$N" --qps "$WARM_QPS" \
        --duration 1 --warmup "$WARMUP" --seed "$SEED" --keep-up )

    first=1
    for q in $QPS_LEVELS; do
        [ "$first" -eq 1 ] || { note "drain ${DRAIN}s before next level"; sleep "$DRAIN"; }
        first=0
        dest="$A2_DIR/sweep${s}/q${q}"
        run_level "$dest" "$q"
        echo "sweep=$s qps=$q dur=$DURATION mw=$(mw_for "$q") -> results/a2/sweep${s}/q${q}/client.csv" >> "$MANIFEST"
    done

    note "sweep $s complete — tearing down the ring"
    teardown_ring
done

note "collection complete — snapshots under $A2_DIR (see MANIFEST.txt)"
note "next: python3 experiments/a2_throughput.py"
