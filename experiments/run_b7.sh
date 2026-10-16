#!/usr/bin/env bash
# Issue #48 [B7] — Denial of service: data collection (Phase 7, examiner point (ii)).
#
# B7 holds the ring FIXED at N=32 (frozen emulation ceiling, PARAMETERS.md §1), s=3. It measures
# the effect on HONEST clients of a DoS, with the MANDATORY honest-control (same traffic volume,
# honest sources) so the protocol-attributable DoS is separated from chord.py's load fragility —
# the issue's core requirement. Two blocks:
#
#   FLOOD (primary) — a host-side flooder (experiments/b7_flooder.py) blasts the honest ring with
#     high-rate find_successor RPCs at offered intensity R. Measured per R, per arm:
#       * arm=attack   — flooder --pattern junk  (random keys -> full iterative lookups)
#       * arm=control  — NO flooder; instead extra LEGITIMATE load at the same offered rate R
#                        (query_gen --qps R, honest), the "same volume, honest sources" baseline.
#     The ring is ALL-HONEST in both arms (the flood is external); the probe is query_gen at the
#     frozen 10 qps into the honest seed node 0 (--ring-nodes 1). protocol delta = control − attack.
#
#   BLACKHOLE (secondary) — f in {0,10,..,50}% of nodes run MALICIOUS_MODE=drop (reuses B3's
#     plumbing), reframed onto the SYSTEMIC honest query stream (all Zipf queries, not one censored
#     chunk). f=0 is the shared honest control.
#
# Beside the client impact, each point snapshots RING HEALTH (experiments/b7_ringhealth.py over every
# node's debug_state): % correct immediate successors + orphans — the chord.py fragility quantified
# (a flood that starves stabilize makes nodes shed successors). THIS is where that fragility matters
# most (issue #48), so the control arm is what tells apart "the ring buckles under any load" from
# "the adversary did it".
#
# This script ONLY collects raw data; the table/plot are produced by experiments/b7_dos.py +
# experiments/plot_b7.py. No frozen artifact is edited (flooder is host-side; drop already exists).
#
# Frozen workload (PARAMETERS.md): N=32, s=3, probe 10 qps, Zipf alpha=1.0 / 1000 Tranco domains,
# netem 5/50 ms, seed 20260919, delta=2 s, PLOT_N=1024, DRG delta=2. UPSTREAM_TTL=0 (A2/B3 cold-path)
# so caching never masks the attack (default 300 keeps A1-A6 byte-identical).
#
# Usage:
#   bash experiments/run_b7.sh                                             # flood sweep + blackhole
#   B7_INTENSITY="0 200" B7_RUNS=1 B7_DURATION=20 bash experiments/run_b7.sh   # quick smoke
#   B7_BLACKHOLE=0 bash experiments/run_b7.sh                              # flood block only
#   B7_FLOOD=0     bash experiments/run_b7.sh                              # blackhole block only
#
# Requires: Docker Desktop running (brings up 32 ring containers + netem).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
B7_DIR="$RESULTS/b7"

# knobs (env-overridable for smoke runs)
INTENSITY="${B7_INTENSITY:-0 50 100 200 400}"   # offered flood rate R (RPC/s) for the flood sweep
F_LEVELS="${B7_F:-0 10 20 30 40 50}"            # adversary fraction f (percent) for blackhole
N="${B7_N:-32}"
RUNS="${B7_RUNS:-3}"
PROBE_QPS="${B7_PROBE_QPS:-10}"                 # honest probe load (frozen)
DURATION="${B7_DURATION:-120}"                  # measured window
WARMUP="${B7_WARMUP:-30}"
WARM_QPS="${B7_WARM_QPS:-10}"
SEED="${B7_SEED:-20260919}"
ALPHA="${B7_ALPHA:-1.0}"
SYNC="${B7_SYNC:-3}"
DNS_PORT="${B7_DNS_PORT:-5300}"
RING_PORT="${B7_RING_PORT:-7000}"
IP_PREFIX="${B7_IP_PREFIX:-172.30.0}"
IP_BASE="${B7_IP_BASE:-10}"
S="${B7_S:-3}"
UPSTREAM_TTL="${B7_UPSTREAM_TTL:-0}"
DO_FLOOD="${B7_FLOOD:-1}"
DO_BLACKHOLE="${B7_BLACKHOLE:-1}"
RINGNET="rpos-ring_ringnet"
IMG="rpos-node:latest"

note() { echo "== [B7] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ] || fail "missing $TESTBED/run_experiment.sh"
[ -f "$TESTBED/query_gen.py" ]      || fail "missing $TESTBED/query_gen.py"
[ -f "$HERE/b7_placement.py" ]      || fail "missing $HERE/b7_placement.py"
[ -f "$HERE/b7_flooder.py" ]        || fail "missing $HERE/b7_flooder.py"
[ -f "$HERE/b7_ringhealth.py" ]     || fail "missing $HERE/b7_ringhealth.py"

mkdir -p "$B7_DIR"
MANIFEST="$B7_DIR/MANIFEST.txt"
: > "$MANIFEST"
{
    echo "# B7 collection manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# N=$N s=$S probe_qps=$PROBE_QPS duration=$DURATION warmup=$WARMUP@${WARM_QPS}qps "\
"seed=$SEED intensity='$INTENSITY' f_levels='$F_LEVELS' runs=$RUNS upstream_ttl=$UPSTREAM_TTL "\
"flood=$DO_FLOOD blackhole=$DO_BLACKHOLE"
} >> "$MANIFEST"

teardown_ring() {
    ( cd "$TESTBED" && docker compose -f docker-compose.nodes.yml down -v >/dev/null 2>&1 ) || true
    ( cd "$TESTBED" && NETWORK="$RINGNET" ./netem.sh clear >/dev/null 2>&1 ) || true
}
trap teardown_ring EXIT

mw_for() { local q="$1"; local mw=$(( q * 5 )); [ "$mw" -lt 64 ] && mw=64; [ "$mw" -gt 1024 ] && mw=1024; echo "$mw"; }

# bring the ring up (converge + warm @ WARM_QPS) and leave it up. idx = malicious indices (drop),
# empty for the all-honest flood arms.
bring_up() {   # <malicious-indices> <malicious-mode>
    local idx="$1" mode="${2:-drop}"
    ( cd "$TESTBED" && UPSTREAM_TTL="$UPSTREAM_TTL" ./run_experiment.sh --mode nodes --nodes "$N" \
        --qps "$WARM_QPS" --duration 1 --warmup "$WARMUP" --seed "$SEED" \
        --replication "$S" --malicious-indices "$idx" --malicious-mode "$mode" --keep-up )
}

# honest probe: query_gen at PROBE_QPS into node 0 (honest entry), writing client.csv.
probe() {   # <out-dir>
    local dest="$1" mw; mw="$(mw_for "$PROBE_QPS")"
    docker run --rm --network "$RINGNET" -v "$REPO_ROOT":/repo -v "$dest":/out -w /repo/testbed \
        "$IMG" python query_gen.py --qps "$PROBE_QPS" --duration "$DURATION" --alpha "$ALPHA" \
            --seed "$SEED" --ring-nodes 1 --ring-dns-port "$DNS_PORT" --max-workers "$mw" \
            --output "/out/client.csv"
}

# ring-health snapshot (every node's debug_state) while up -> dest/ringhealth.json.
ringhealth() {   # <out-dir>
    docker run --rm --network "$RINGNET" -v "$REPO_ROOT":/repo -v "$1":/out -w /repo \
        "$IMG" python experiments/b7_ringhealth.py --nodes "$N" --prefix "$IP_PREFIX" \
            --base "$IP_BASE" --ring-port "$RING_PORT" --output "/out/ringhealth.json" || true
}

snapshot_node0() {   # <out-dir>  (raw-DHT outcome signal for the blackhole block)
    mkdir -p "$1/ring"
    [ -f "$RESULTS/ring/0/queries.csv" ] && cp "$RESULTS/ring/0/queries.csv" "$1/ring/0_queries.csv" || true
}

# ---- BLOCK 1: flood sweep (attack = junk flooder; control = matched honest load) ----------------
if [ "$DO_FLOOD" -eq 1 ]; then
    for R in $INTENSITY; do
        for r in $(seq 1 "$RUNS"); do
            # --- attack arm: all-honest ring + junk flooder at rate R ---
            dest="$B7_DIR/flood/attack/i${R}/run${r}"; mkdir -p "$dest"
            tgt="$(python3 "$HERE/b7_placement.py" --role flood --flood broad --n "$N" --s "$S" \
                     --seed "$SEED" --out "$dest/placement.json")"
            note "FLOOD attack R=${R}/s run=$r/$RUNS (targets=broad)"
            bring_up "" drop
            : > "$RESULTS/ring/0/queries.csv" 2>/dev/null || true
            if [ "$R" -gt 0 ]; then
                docker run -d --name "b7flood_${R}_${r}" --network "$RINGNET" \
                    -v "$REPO_ROOT":/repo -v "$dest":/out -w /repo "$IMG" \
                    python experiments/b7_flooder.py --ring-nodes "$N" --targets "$tgt" \
                        --rate "$R" --duration "$DURATION" --pattern junk \
                        --ring-ip-prefix "$IP_PREFIX" --ring-ip-base "$IP_BASE" \
                        --ring-port "$RING_PORT" --seed "$SEED" --output /out/flood.json >/dev/null
            fi
            probe "$dest"
            ringhealth "$dest"
            if [ "$R" -gt 0 ]; then
                docker logs "b7flood_${R}_${r}" > "$dest/flood.log" 2>&1 || true
                docker rm -f "b7flood_${R}_${r}" >/dev/null 2>&1 || true
            fi
            sleep "$SYNC"; snapshot_node0 "$dest"; teardown_ring
            echo "flood attack R=$R run=$r -> results/b7/flood/attack/i${R}/run${r}/" >> "$MANIFEST"

            # --- control arm: all-honest ring + matched LEGITIMATE load at rate R ---
            dest="$B7_DIR/flood/control/i${R}/run${r}"; mkdir -p "$dest"
            note "FLOOD control R=${R}/s run=$r/$RUNS (matched honest load)"
            bring_up "" drop
            : > "$RESULTS/ring/0/queries.csv" 2>/dev/null || true
            if [ "$R" -gt 0 ]; then
                mw="$(mw_for "$R")"
                docker run -d --name "b7load_${R}_${r}" --network "$RINGNET" \
                    -v "$REPO_ROOT":/repo -w /repo/testbed "$IMG" \
                    python query_gen.py --qps "$R" --duration "$DURATION" --alpha "$ALPHA" \
                        --seed "$((SEED + 7))" --ring-nodes "$N" --ring-dns-port "$DNS_PORT" \
                        --max-workers "$mw" --output "/repo/results/b7_control_load.csv" >/dev/null
            fi
            probe "$dest"
            ringhealth "$dest"
            [ "$R" -gt 0 ] && { docker rm -f "b7load_${R}_${r}" >/dev/null 2>&1 || true; }
            sleep "$SYNC"; snapshot_node0 "$dest"; teardown_ring
            echo "flood control R=$R run=$r -> results/b7/flood/control/i${R}/run${r}/" >> "$MANIFEST"
        done
    done
fi

# ---- BLOCK 2: blackhole f-grid (drop nodes; systemic honest-query impact) ------------------------
if [ "$DO_BLACKHOLE" -eq 1 ]; then
    for f in $F_LEVELS; do
        nmal="$(python3 -c "print(round($f/100*$N))")"
        for r in $(seq 1 "$RUNS"); do
            dest="$B7_DIR/blackhole/f${f}/run${r}"; mkdir -p "$dest"
            pseed=$(( SEED + r ))
            idx="$(python3 "$HERE/b7_placement.py" --role blackhole --n "$N" --s "$S" \
                     --n-mal "$nmal" --seed "$pseed" --out "$dest/placement.json")"
            note "BLACKHOLE f=${f}% (n_mal=$nmal) run=$r/$RUNS — drop=[${idx:-none}]"
            bring_up "$idx" drop
            : > "$RESULTS/ring/0/queries.csv" 2>/dev/null || true
            probe "$dest"
            ringhealth "$dest"
            sleep "$SYNC"; snapshot_node0 "$dest"; teardown_ring
            echo "blackhole f=$f n_mal=$nmal run=$r indices='${idx}' -> results/b7/blackhole/f${f}/run${r}/" >> "$MANIFEST"
        done
    done
fi

note "collection complete — snapshots under $B7_DIR (see MANIFEST.txt)"
note "next: python3 experiments/b7_dos.py && python3 experiments/plot_b7.py"
