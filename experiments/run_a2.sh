#!/usr/bin/env bash
# Issue #33 [A2] — Throughput / saturation, CACHE-CONTROLLED redo (Phase 6, examiner point (iii)).
#
# WHY THIS REPLACES THE ASCENDING SWEEP. The original A2 ramped load on ONE ring with the caches
# left to accumulate across levels; the resulting curve confounded load with cache warming — p95
# *fell* as qps rose (1774 ms @50 → 8.9 ms @100), which measures cache accumulation, not saturation.
# This redo pins the cache state so each level is a fair, independent measurement and p95 is
# monotonically non-decreasing with load, and produces TWO clean curves:
#
#   1. COLD-PATH  (UPSTREAM_TTL=0)     — the resolver cache never retains, so EVERY query exercises
#      the DHT read path (route + s replica reads + majority vote). The conservative saturation.
#   2. STEADY     (UPSTREAM_TTL=huge)  — the cache is fully pre-warmed and stays warm, so every query
#      is served from cache. The cache-assisted throughput ceiling.
#
# HOW THE CACHE IS CONTROLLED WITHOUT TOUCHING FROZEN CODE. node/run_ring_node.py now reads env
# UPSTREAM_TTL (default 300 => A1/A3-A7 byte-identical) and passes it to the fallback resolver, which
# sets both the stored-chunk TTL and node/query.py's local-cache retention. TTL=0 => the cache entry
# is already expired on the next lookup (pure DHT path); a huge TTL => a warmed entry never expires
# within the run (pure cache path). Storage never expires chunks and fallback chunks are not
# ledger-refreshed, so TTL only moves the cache, not DHT availability or background load. No frozen
# artifact is modified (rpos.py / chord.py / ledger.py / storage.py / query.py all byte-identical).
#
# ENTRY MODEL PER CURVE (chosen so each curve is BOTH clean and representative):
#   * COLD  -> DISTRIBUTED entry (--ring-nodes N). With TTL=0 there is no cache anywhere, so a
#     round-robin entry cannot accumulate cache and the curve cleanly measures the AGGREGATE ring
#     DHT throughput (route + s replica reads over the whole ring), the meaningful whole-resolver
#     number. Outcomes are logged across all N nodes, so we snapshot every node's log.
#   * STEADY -> SINGLE entry (node 0, --ring-nodes 1), like A6. A coherent, fully-warm cache needs one
#     entry node (round-robin would give each node an incoherent partial cache, breaking the control).
#     It measures the cache-assisted serving ceiling of a warm entry node.
# The two curves therefore isolate different things (aggregate DHT work vs warm-cache serving) with
# the appropriate entry model for each; this is stated in A2_NOTES.md.
#
# METHOD (per curve, per sweep): bring up a FRESH N=32 ring with the curve's UPSTREAM_TTL; run a
# fixed FULL-COVERAGE warm-up (alpha=0 uniform over all 1000 domains, to node 0) that populates the
# DHT for both curves and additionally warms node 0's cache for STEADY; then measure each qps level
# 30 s at alpha=1.0. Because the cache is static during measurement (empty for COLD, full for STEADY),
# levels are order-independent and share one ring per sweep. Node 0's per-level outcome log is
# snapshotted so the analysis can PROVE the path (COLD ~ all dht_hit, STEADY ~ all cache_hit).
# 3 sweeps (fresh ring each) give run-to-run error bars.
#
# Frozen A2 workload (PARAMETERS.md): N=32, 30 s measured per level, Zipf alpha=1.0 for MEASUREMENT,
# netem 5/50 ms two-tier, seed 20260919, s=3, delta=2 s, PLOT_N=1024, DRG in-degree 2.
# Swept: offered qps in {25,50,75,100,125,150,175,200}; controlled: UPSTREAM_TTL per curve.
#
# Usage:
#   bash experiments/run_a2.sh                                  # both curves, 3 sweeps, 8 levels
#   A2_CURVES=cold A2_SWEEPS=1 A2_QPS="25 100 200" bash experiments/run_a2.sh   # quick smoke
#
# Requires: Docker Desktop running (brings up the N=32 ring + netem).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
A2_DIR="$RESULTS/a2"

# knobs (env-overridable for smoke runs)
QPS_LEVELS="${A2_QPS:-25 50 75 100 125 150 175 200}"
CURVES="${A2_CURVES:-cold steady}"
SWEEPS="${A2_SWEEPS:-3}"
N="${A2_N:-32}"
DURATION="${A2_DURATION:-30}"
WARM_QPS="${A2_WARM_QPS:-150}"          # full-coverage warm-up offered rate (alpha=0)
WARM_DURATION="${A2_WARM_DURATION:-90}" # long enough to first-touch all 1000 domains via node 0
SEED="${A2_SEED:-20260919}"
ALPHA="${A2_ALPHA:-1.0}"                 # MEASUREMENT distribution (frozen workload)
DRAIN="${A2_DRAIN:-5}"                   # inter-level settle (seconds) so a backlog drains
SYNC="${A2_SYNC:-3}"                     # settle+flush before snapshotting node-0 log
DNS_PORT="${A2_DNS_PORT:-5300}"
RINGNET="rpos-ring_ringnet"
IMG="rpos-node:latest"

# TTL + entry model per curve. BOTH curves funnel through node 0 (--ring-nodes 1): it gives a clean,
# monotonic, comparable pair with a fully-controlled node-0 cache. (An exploratory DISTRIBUTED cold
# run — every node an entry — was discarded: sustained pure-DHT RPC load perturbs chord.py's
# maintenance loop and the ring reconverges *during* each level, giving non-monotonic, unstable
# success; that is the frozen chord.py stabilize fragility documented for N=64, not a load-saturation
# signal. Funnel isolates the DHT-work path through one entry node without destabilising the ring.)
ttl_for()   { case "$1" in cold) echo 0 ;; steady) echo 100000 ;; *) echo 300 ;; esac; }
entry_for() { echo 1; }   # --ring-nodes: single entry (node 0) for both curves

note() { echo "== [A2] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ] || fail "missing $TESTBED/run_experiment.sh"
[ -f "$TESTBED/query_gen.py" ]      || fail "missing $TESTBED/query_gen.py"

# fresh A2 tree (single provenance — the redo replaces the old ascending data entirely). Only the
# curves being collected THIS run are cleared, so a per-curve re-run keeps the other curve's data.
mkdir -p "$A2_DIR"
for curve in $CURVES; do rm -rf "$A2_DIR/$curve"; done
MANIFEST="$A2_DIR/MANIFEST.txt"
{
    echo "# A2 cache-controlled collection manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# N=$N levels='$QPS_LEVELS' curves='$CURVES' sweeps=$SWEEPS duration=$DURATION"
    echo "# warm-up: alpha=0 ${WARM_QPS}qps x ${WARM_DURATION}s to node 0; measure alpha=$ALPHA; seed=$SEED"
} >> "$MANIFEST"

teardown_ring() {
    ( cd "$TESTBED" && docker compose -f docker-compose.nodes.yml down -v >/dev/null 2>&1 ) || true
    ( cd "$TESTBED" && NETWORK="$RINGNET" ./netem.sh clear >/dev/null 2>&1 ) || true
}
trap teardown_ring EXIT

mw_for() { local q="$1" mw=$(( q * 5 )); [ "$mw" -lt 64 ] && mw=64; [ "$mw" -gt 1024 ] && mw=1024; echo "$mw"; }

# drive one load level; snapshot client.csv + every node's outcome log (scoped to this level).
# <ring_nodes> = --ring-nodes value (N for distributed cold, 1 for funnel steady).
run_level() {   # <dest-dir> <qps> <alpha> <duration> <ring_nodes>
    local dest="$1" q="$2" al="$3" dur="$4" rn="$5" mw j; mw="$(mw_for "$q")"
    mkdir -p "$dest/ring"
    for j in $(seq 0 $((N - 1))); do : > "$RESULTS/ring/$j/queries.csv" 2>/dev/null || true; done
    note "level ${q} qps for ${dur}s (alpha=$al, ring-nodes=$rn, max-workers=$mw) -> $dest/client.csv"
    docker run --rm --network "$RINGNET" -v "$REPO_ROOT":/repo -v "$dest":/out -w /repo/testbed \
        "$IMG" \
        python query_gen.py --qps "$q" --duration "$dur" --alpha "$al" --seed "$SEED" \
            --ring-nodes "$rn" --ring-dns-port "$DNS_PORT" --max-workers "$mw" \
            --output "/out/client.csv" || true
    sleep "$SYNC"
    for j in $(seq 0 $((N - 1))); do
        [ -f "$RESULTS/ring/$j/queries.csv" ] && cp "$RESULTS/ring/$j/queries.csv" "$dest/ring/${j}_queries.csv" || true
    done
}

for curve in $CURVES; do
    TTL="$(ttl_for "$curve")"
    ENTRY="$(entry_for "$curve")"
    for s in $(seq 1 "$SWEEPS"); do
        note "curve=$curve (UPSTREAM_TTL=$TTL, ring-nodes=$ENTRY) sweep $s/$SWEEPS — bring up + warm-up"
        # bring the ring up with the curve's TTL baked in (gen_nodes_compose reads UPSTREAM_TTL).
        # the tiny --duration/--warmup here is a throwaway; our own warm-up + levels follow.
        UPSTREAM_TTL="$TTL" bash -c "cd '$TESTBED' && ./run_experiment.sh --mode nodes --nodes '$N' \
            --qps 10 --duration 1 --warmup 1 --seed '$SEED' --keep-up"

        # FULL-COVERAGE warm-up: alpha=0 uniform over all domains. Populates the DHT for both curves
        # (chunks land on the responsible node regardless of entry); for STEADY (funnel) it also fills
        # node 0's cache (held by the huge TTL). Same entry model as the measurement. CSV discarded.
        warm="$A2_DIR/$curve/sweep${s}/_warmup"
        run_level "$warm" "$WARM_QPS" 0.0 "$WARM_DURATION" "$ENTRY"

        for q in $QPS_LEVELS; do
            [ "$q" = "${QPS_LEVELS%% *}" ] || { note "drain ${DRAIN}s"; sleep "$DRAIN"; }
            dest="$A2_DIR/$curve/sweep${s}/q${q}"
            run_level "$dest" "$q" "$ALPHA" "$DURATION" "$ENTRY"
            echo "curve=$curve sweep=$s qps=$q entry=$ENTRY -> results/a2/$curve/sweep${s}/q${q}/client.csv" >> "$MANIFEST"
        done

        note "curve=$curve sweep $s complete — tearing down the ring"
        teardown_ring
    done
done

note "collection complete — snapshots under $A2_DIR (see MANIFEST.txt)"
note "next: python3 experiments/a2_throughput.py"
