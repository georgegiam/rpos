#!/usr/bin/env bash
# Issue #37 [A6] — Churn: lookup success vs session length: data collection (Phase 6, points (ii)/(iii)).
#
# A6 holds the ring FIXED at N=32 (the frozen emulation ceiling, PARAMETERS.md §1) and 10 qps, and
# sweeps the MEAN NODE SESSION LENGTH over {30, 60, 120, 300, inf} seconds (inf = no churn control),
# 3 runs each. It measures how membership churn erodes lookup availability. This script ONLY collects
# the emulation raw data; the table / plot / sim cross-check are produced by experiments/a6_churn.py.
#
# THE NEW PRIMITIVE — a churn injector. The testbed has no graceful leave (node/chord.py has no
# leave()); the realistic departure is an ungraceful crash detected by socket_net.is_up() (3-fail
# threshold) and healed by stabilize. experiments/a6_churn_injector.py drives that by
# docker kill / docker start on the ring containers (indices 1..N-1; node 0 = seed/bootstrap is never
# churned) on a seeded per-node alternating-renewal schedule (UP ~ Exp(mean_session), DOWN ~
# Exp(downtime)). It touches NO protocol code and NO frozen artifact (CLAUDE.md §2) — only containers
# the compose file already created.
#
# QUERIES ENTER AT NODE 0 (--ring-nodes 1). A6 measures data/route AVAILABILITY on the ring, not
# "did the specific node I asked happen to be dead" — so all measured queries go to node 0 (always
# alive), which does the Chord routing; a miss then reflects chunk/route unavailability. At 10 qps
# concentrating the load on node 0 is negligible. (Flagged in A6_NOTES.md.)
#
# HEADLINE METRIC = raw-DHT success (a fallback = a DHT miss), recovered by joining the client CSV to
# the node-side outcome log (the A1 join) — end-to-end client success would stay ~100% because the
# resolver fallback re-fetches lost chunks, flattening the curve. Both are reported; raw-DHT is the
# headline (comparable to sim/churn_sim.py).
#
# METHODOLOGY — A4's proven bring-up (warm @ 10 qps then measure, snapshot ring logs WHILE UP), with
# the injector launched in the background over the measured window:
# per (session L, run): bring up N=32 + converge + warm @ 10 qps ONCE (--keep-up), truncate the node
# logs to scope them to the measured window, launch the churn injector (skipped for inf) AND drive the
# measured 10 qps load concurrently, snapshot client.csv + each node's queries.csv + churn_events.csv
# WHILE UP, then tear down. Repeated 3x per L for run-to-run error bars.
#
# New code in a new file (CLAUDE.md §2): touches no protocol code and no frozen artifact. Reuses
# testbed/run_experiment.sh --mode nodes ... --keep-up (bring-up) and testbed/query_gen.py (load).
#
# Frozen A6 workload (PARAMETERS.md): N=32, 10 qps, 120 s measured, 30 s warm-up @ 10 qps, Zipf
# alpha=1.0 over 1000 Tranco domains, netem 5/50 ms two-tier, seed 20260919, δ=2 s, PLOT_N=1024,
# DRG δ=2, s=3. Swept: mean session length in {30,60,120,300,inf}.
#
# Usage:
#   bash experiments/run_a6.sh                                # full matrix: sessions x 3 runs
#   A6_SESSIONS="300 inf" A6_RUNS=1 bash experiments/run_a6.sh  # quick smoke subset
#
# Requires: Docker Desktop running (the testbed brings up 32 ring containers + netem).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
A6_DIR="$RESULTS/a6"

# knobs (env-overridable for smoke runs)
SESSIONS="${A6_SESSIONS:-30 60 120 300 inf}"   # mean session lengths (s); inf = no-churn control
N="${A6_N:-32}"
RUNS="${A6_RUNS:-3}"
QPS="${A6_QPS:-10}"
DURATION="${A6_DURATION:-120}"                 # measured window (issue #37)
WARMUP="${A6_WARMUP:-30}"
WARM_QPS="${A6_WARM_QPS:-10}"                   # low, converging warm-up load (A2/A3's lesson)
DOWNTIME="${A6_DOWNTIME:-5}"                    # mean rejoin gap after a kill (injector default)
SEED="${A6_SEED:-20260919}"
ALPHA="${A6_ALPHA:-1.0}"
SYNC="${A6_SYNC:-3}"                            # settle+flush seconds after load, before snapshotting
DNS_PORT="${A6_DNS_PORT:-5300}"
RINGNET="rpos-ring_ringnet"                     # matches run_experiment.sh's RINGNET
IMG="rpos-node:latest"

note() { echo "== [A6] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ] || fail "missing $TESTBED/run_experiment.sh"
[ -f "$TESTBED/query_gen.py" ]      || fail "missing $TESTBED/query_gen.py"
[ -f "$HERE/a6_churn_injector.py" ] || fail "missing $HERE/a6_churn_injector.py"

mkdir -p "$A6_DIR"
MANIFEST="$A6_DIR/MANIFEST.txt"
: > "$MANIFEST"
{
    echo "# A6 collection manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# N=$N qps=$QPS duration=$DURATION warmup=$WARMUP@${WARM_QPS}qps downtime=$DOWNTIME "\
"seed=$SEED sessions='$SESSIONS' runs=$RUNS"
} >> "$MANIFEST"

# filesystem-safe tag for a session length (30 -> s30, inf -> sinf)
stag() { echo "s$1"; }

# tear the ring down (compose + netem). Idempotent — safe on a mid-run abort.
teardown_ring() {
    ( cd "$TESTBED" && docker compose -f docker-compose.nodes.yml down -v >/dev/null 2>&1 ) || true
    ( cd "$TESTBED" && NETWORK="$RINGNET" ./netem.sh clear >/dev/null 2>&1 ) || true
}
trap teardown_ring EXIT   # safety net: whatever is up when the script exits gets cleaned up

# max-workers sized so the generator never caps below the ring (A2's clamp: qps × 5 s timeout).
mw_for() { local q="$1"; local mw=$(( q * 5 )); [ "$mw" -lt 64 ] && mw=64; [ "$mw" -gt 1024 ] && mw=1024; echo "$mw"; }

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

# ---- resolver ring: sessions x runs at fixed N=32 and the A6 load -------------------------------
for L in $SESSIONS; do
    tag="$(stag "$L")"
    for r in $(seq 1 "$RUNS"); do
        dest="$A6_DIR/$tag/run${r}"
        mkdir -p "$dest"
        note "session=$L run=$r/$RUNS — bring up N=$N + warm ${WARMUP}s @ ${WARM_QPS} qps, then measure @ ${QPS} qps under churn"
        # bring up + converge + warm ONCE at WARM_QPS, leave the ring up (--keep-up). The throwaway
        # --duration 1 measured run is ignored; the real A6 load is driven below (s=3 defaults).
        ( cd "$TESTBED" && ./run_experiment.sh --mode nodes --nodes "$N" --qps "$WARM_QPS" \
            --duration 1 --warmup "$WARMUP" --seed "$SEED" --keep-up )

        # scope node logs to the measured window
        for j in $(seq 0 $((N - 1))); do : > "$RESULTS/ring/$j/queries.csv" 2>/dev/null || true; done

        # launch churn injector in the background over the measured window (no-op for inf)
        note "launching churn injector (mean_session=$L s, downtime=$DOWNTIME s) for ${DURATION}s"
        python3 "$HERE/a6_churn_injector.py" --nodes "$N" --mean-session "$L" \
            --duration "$DURATION" --mean-downtime "$DOWNTIME" --seed "$SEED" \
            --events-out "$dest/churn_events.csv" &
        injector_pid=$!

        # drive the measured load — ALL queries enter at node 0 (--ring-nodes 1) to isolate
        # availability (a query never fails just because the node it was sent to is currently dead).
        mw="$(mw_for "$QPS")"
        note "measured ${QPS} qps for ${DURATION}s via node 0 (max-workers=$mw) -> $dest/client.csv"
        docker run --rm --network "$RINGNET" -v "$REPO_ROOT":/repo -v "$dest":/out -w /repo/testbed \
            "$IMG" \
            python query_gen.py --qps "$QPS" --duration "$DURATION" --alpha "$ALPHA" --seed "$SEED" \
                --ring-nodes 1 --ring-dns-port "$DNS_PORT" --max-workers "$mw" \
                --output "/out/client.csv" || true

        note "waiting for churn injector to finish"
        wait "$injector_pid" || true

        note "settle ${SYNC}s so the node logs flush to the host mount, then snapshot"
        sleep "$SYNC"
        snapshot_ring "$dest" "$N"

        note "session=$L run=$r complete — tearing down the ring"
        teardown_ring
        echo "nodes session=$L N=$N run=$r -> results/a6/$tag/run${r}/{client.csv,churn_events.csv,ring/}" >> "$MANIFEST"
    done
done

note "collection complete — snapshots under $A6_DIR (see MANIFEST.txt)"
note "next: python3 experiments/a6_churn.py"
