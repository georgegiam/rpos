#!/usr/bin/env bash
# Issue #32 [A1] — Latency vs N: data collection.
#
# Phase 6 experiment A1 measures end-to-end query latency of the resolver ring as a function of
# ring size N (4, 8, 16, 32 — all within the frozen N=32 emulation ceiling, PARAMETERS.md §1),
# 3 runs each, plus a matching Unbound baseline. This script ONLY collects the raw data; the
# analysis / table / plot are produced by experiments/a1_latency_vs_n.py.
#
# It is a thin loop over the existing testbed/run_experiment.sh (CLAUDE.md §2: new code in new
# files; it touches no protocol code and no frozen artifact). Its one real job beyond looping is
# to SNAPSHOT each run's two log halves before the next run destroys them:
#
#   * client latency CSV  results/exp_*_N<n>_*_nodes.csv   (timestamp,domain,resolver_used,
#                                                            latency_ms,success) — no outcome
#   * per-node ring logs  results/ring/<j>/queries.csv     (timestamp,domain,hops,outcome,
#                                                            vote_result) — no latency
#
# run_experiment.sh TRUNCATES results/ring/<j>/queries.csv before every measured run
# (run_experiment.sh line ~201) and the next run overwrites it, so the node-side outcome data
# for run r survives only until run r+1 starts. We copy both halves into results/a1/N<n>/run<r>/
# straight after each run returns; a1_latency_vs_n.py then joins latency<->outcome from there.
#
# Frozen A1 workload (PARAMETERS.md): 10 qps, 30 s measured, 30 s warm-up (15 s for the Unbound
# baseline), Zipf alpha=1.0 over 1000 Tranco domains, netem 5/50 ms two-tier, seed 20260919.
# A1 is a LATENCY experiment, so the offered load is the unsaturated 10 qps; saturation is A2.
#
# Usage:
#   bash experiments/run_a1.sh                 # full matrix: N in {4,8,16,32} x 3 + Unbound x 3
#   A1_NS="8 32" A1_RUNS=1 bash experiments/run_a1.sh   # quick smoke subset
#   A1_SKIP_UNBOUND=1 bash experiments/run_a1.sh        # resolver ring only
#
# Requires: Docker Desktop running (the testbed brings up NSD/Unbound + N ring containers).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
A1_DIR="$RESULTS/a1"

# knobs (env-overridable for smoke runs)
NS="${A1_NS:-4 8 16 32}"
RUNS="${A1_RUNS:-3}"
QPS="${A1_QPS:-10}"
DURATION="${A1_DURATION:-30}"
WARMUP="${A1_WARMUP:-30}"
UNBOUND_WARMUP="${A1_UNBOUND_WARMUP:-15}"
SEED="${A1_SEED:-20260919}"
SKIP_UNBOUND="${A1_SKIP_UNBOUND:-0}"

note() { echo "== [A1] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ] || fail "missing $TESTBED/run_experiment.sh"

mkdir -p "$A1_DIR"
MANIFEST="$A1_DIR/MANIFEST.txt"
: > "$MANIFEST"
echo "# A1 collection manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$MANIFEST"
echo "# qps=$QPS duration=$DURATION warmup=$WARMUP seed=$SEED ns='$NS' runs=$RUNS" >> "$MANIFEST"

# newest results/exp_*<suffix>.csv (the client CSV run_experiment.sh just wrote)
newest_client_csv() {
    ls -t "$RESULTS"/exp_*"$1".csv 2>/dev/null | head -n1
}

# snapshot the client CSV + this run's ring/<j>/queries.csv (j in 0..N-1) into dest/.
# Scoped to exactly this run's N nodes: results/ring/ can hold stale higher-index dirs from
# earlier, larger-N runs (run_experiment.sh only truncates ring/0..N-1), and copying those
# would drag in another run's node logs.
snapshot() {   # <dest-dir> <client-csv> <N>
    local dest="$1" client="$2" n="$3" j found=0
    mkdir -p "$dest/ring"
    [ -n "$client" ] && [ -f "$client" ] && cp "$client" "$dest/client.csv" \
        || echo "  [warn] no client CSV to snapshot for $dest" >&2
    for j in $(seq 0 $((n - 1))); do
        if [ -f "$RESULTS/ring/$j/queries.csv" ]; then
            cp "$RESULTS/ring/$j/queries.csv" "$dest/ring/${j}_queries.csv"
            found=$((found + 1))
        fi
    done
    echo "  snapshotted client + $found/$n ring logs -> $dest"
}

# ---- resolver ring: N x runs ----------------------------------------------------------------
for N in $NS; do
    for r in $(seq 1 "$RUNS"); do
        dest="$A1_DIR/N${N}/run${r}"
        note "nodes-mode N=$N run=$r/$RUNS (qps=$QPS dur=$DURATION warmup=$WARMUP)"
        ( cd "$TESTBED" && ./run_experiment.sh --mode nodes --nodes "$N" --qps "$QPS" \
            --duration "$DURATION" --warmup "$WARMUP" --seed "$SEED" )
        client="$(newest_client_csv "_N${N}_q${QPS}_d${DURATION}_nodes")"
        mkdir -p "$dest"
        snapshot "$dest" "$client" "$N"
        echo "nodes N=$N run=$r client=$(basename "${client:-none}")" >> "$MANIFEST"
    done
done

# ---- Unbound baseline: N-independent, so collected once, RUNS times -------------------------
if [ "$SKIP_UNBOUND" != "1" ]; then
    for r in $(seq 1 "$RUNS"); do
        dest="$A1_DIR/unbound/run${r}"
        note "host-mode Unbound baseline run=$r/$RUNS (qps=$QPS dur=$DURATION warmup=$UNBOUND_WARMUP)"
        ( cd "$TESTBED" && ./run_experiment.sh --mode host --qps "$QPS" \
            --duration "$DURATION" --warmup "$UNBOUND_WARMUP" --seed "$SEED" )
        client="$(newest_client_csv "_N8_q${QPS}_d${DURATION}")"   # host mode: default N=8 tag, no _nodes
        mkdir -p "$dest"
        [ -n "$client" ] && [ -f "$client" ] && cp "$client" "$dest/client.csv" \
            || echo "  [warn] no Unbound client CSV for $dest" >&2
        echo "  snapshotted Unbound client -> $dest"
        echo "unbound run=$r client=$(basename "${client:-none}")" >> "$MANIFEST"
    done
fi

note "collection complete — snapshots under $A1_DIR (see MANIFEST.txt)"
note "next: python3 experiments/a1_latency_vs_n.py"
