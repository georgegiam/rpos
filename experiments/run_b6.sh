#!/usr/bin/env bash
# Issue #47 [B6] — Malicious ledger proposer: OPTIONAL Docker socket cross-check.
#
# The in-process ring (experiments/b6_proposer.py) is the PRIMARY, authoritative measurement and the
# only one that can exercise eviction (socket _evict is a no-op). This script is the optional socket
# anchor (B4 pattern): it brings up a live N=32 ring and confirms that over the REAL wire honest
# replicas commit a FORGED update exactly as a valid one — i.e. the bad-update rejection rate is 0 %
# on the live ring too. It writes a SEPARATE file (results/B6_proposer_socket.csv) so a flaky/slow
# testbed never clobbers the committed primary results/B6_proposer.csv.
#
# It reuses run_a5.sh's proven bring-up (warm @ 10 qps, ring left UP via --keep-up) and then runs
# experiments/b6_driver.py twice against the live ring: --mode valid (honest control) and
# --mode forged (the attack). node/chord.py, node/ledger.py, node/storage.py and rpos/rpos.py stay
# byte-identical (CLAUDE.md §2); admin_propose is the inert A5 diagnostic RPC.
#
# Usage:
#   bash experiments/run_b6.sh                      # N=32, 20 updates each mode, 1 run
#   B6_UPDATES=5 bash experiments/run_b6.sh         # quick smoke subset
#
# Requires: Docker Desktop running (brings up 32 ring containers + netem).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TESTBED="$REPO_ROOT/testbed"
RESULTS="$REPO_ROOT/results"
B6_DIR="$RESULTS/b6"

N="${B6_N:-32}"
UPDATES="${B6_UPDATES:-20}"
PROPOSER="${B6_PROPOSER:-0}"
REPLICATION="${B6_REPLICATION:-3}"
WARMUP="${B6_WARMUP:-30}"
WARM_QPS="${B6_WARM_QPS:-10}"
SEED="${B6_SEED:-20260919}"
INTERVAL_MS="${B6_INTERVAL_MS:-200}"
TIMEOUT="${B6_TIMEOUT:-15}"
SYNC="${B6_SYNC:-3}"
RING_PORT="${B6_RING_PORT:-7000}"
RING_IP_PREFIX="${B6_RING_IP_PREFIX:-172.30.0}"
RING_IP_BASE="${B6_RING_IP_BASE:-10}"
RINGNET="rpos-ring_ringnet"
IMG="rpos-node:latest"
OUT_CSV="$RESULTS/B6_proposer_socket.csv"

note() { echo "== [B6] $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found — Docker Desktop must be running"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable — start Docker Desktop first"
[ -f "$TESTBED/run_experiment.sh" ] || fail "missing $TESTBED/run_experiment.sh"
[ -f "$HERE/b6_driver.py" ]         || fail "missing $HERE/b6_driver.py"

mkdir -p "$B6_DIR"
rm -f "$OUT_CSV"     # fresh socket anchor (header written by the first driver run)

teardown_ring() {
    ( cd "$TESTBED" && docker compose -f docker-compose.nodes.yml down -v >/dev/null 2>&1 ) || true
    ( cd "$TESTBED" && NETWORK="$RINGNET" ./netem.sh clear >/dev/null 2>&1 ) || true
}
trap teardown_ring EXIT

drive() {   # <mode>
    local mode="$1"
    note "driving $UPDATES --mode $mode updates via node-$PROPOSER -> $OUT_CSV"
    docker run --rm --network "$RINGNET" -v "$REPO_ROOT":/repo -v "$RESULTS":/out -w /repo "$IMG" \
        python experiments/b6_driver.py --ring-nodes "$N" --mode "$mode" --updates "$UPDATES" \
            --proposer "$PROPOSER" --replication "$REPLICATION" \
            --ring-ip-prefix "$RING_IP_PREFIX" --ring-ip-base "$RING_IP_BASE" \
            --ring-port "$RING_PORT" --seed "$SEED" --interval-ms "$INTERVAL_MS" \
            --timeout "$TIMEOUT" --manifest /repo/testbed/dns/zones/MANIFEST.json \
            --output /out/B6_proposer_socket.csv
}

note "bring up N=$N (s=$REPLICATION) + warm ${WARMUP}s @ ${WARM_QPS} qps, then drive updates"
( cd "$TESTBED" && ./run_experiment.sh --mode nodes --nodes "$N" --qps "$WARM_QPS" \
    --duration 1 --warmup "$WARMUP" --seed "$SEED" --keep-up )

drive valid       # honest control
drive forged      # the attack
note "settle ${SYNC}s, then tear down the ring"
sleep "$SYNC"
teardown_ring

note "socket cross-check complete -> $OUT_CSV"
