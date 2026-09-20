#!/usr/bin/env bash
# Issue #22 [P3-5] — one-command end-to-end Phase 3 experiment runner.
#
# Chains the four Phase 3 building blocks into a single command with ZERO manual steps:
#   ./up.sh N     -> bring up the DNS tier + Unbound + N resolver nodes
#   ./verify.sh   -> health / recursion done-when gate
#   ./netem.sh    -> apply the two-tier tc link delays
#   query_gen.py  -> drive Zipf load, one CSV row per query
# then summarises the run and tears the stack back down.
#
# This script ONLY orchestrates the existing scripts — it does not touch rpos.py, the compose
# files, the images, or up.sh/netem.sh/verify.sh/query_gen.py (CLAUDE.md §2: new code in new
# files; benchmarked artifacts stay byte-identical).
#
# WHAT IS MEASURED: only Unbound is live end-to-end — the `node` containers are still scaffold
# singletons (see README §"deliberately deferred"). So the load targets Unbound: this run is the
# Unbound baseline (Phase 4/6 A1). The one-line summary and results/experiments.csv label it so.
#
# RESOLVER PATH: default is the host port 127.0.0.1:5300 (query_gen's documented scope). After
# the health gate we probe that port once; if it is dead (the documented macOS Docker Desktop
# host-forward quirk — which would otherwise yield an all-failure, useless CSV) we fall back to
# running query_gen INSIDE a throwaway container on dnsnet, straight at Unbound's static IP
# 172.28.0.7:53. The fallback reuses the already-built rpos-node:latest image (it ships
# dnspython 2.6.1 on Python 3.11 — no pip install) with the repo bind-mounted so query_gen.py +
# dns/ are visible. Passing --resolver forces host mode and skips the probe.
#
# Usage:
#   ./run_experiment.sh --qps Q --duration D [options]
#   ./run_experiment.sh --nodes 8 --qps 20 --duration 15
#
# Options (defaults in []):
#   --nodes N          resolver-node count [8]
#   --qps Q            offered query rate (required)
#   --duration D       measured-run length, seconds (required)
#   --warmup S         warm-up query load before the measured run, seconds [30]
#   --seed S           RNG seed for reproducible sampling [20260919]
#   --alpha A          Zipf exponent [1.0]
#   --no-netem         skip applying tc link delays
#   --regions R        netem regions [2]        --same-ms MS [5]   --cross-ms MS [50]
#   --resolver HOST    force host mode against HOST (skips the probe)
#   --port P           resolver UDP port for host mode [5300]
#   --output-dir DIR   where CSVs land [<repo>/results]
#   --health-timeout S seconds to wait for the stack to become healthy [180]
#   --keep-up          do NOT tear the stack down at the end
#   -h, --help         show this help
#
# Requires: Docker running; for host mode, python3 + dnspython on the host (the in-network
# fallback needs neither). Tear down manually with:
#   docker compose -f testbed/docker-compose.yml down
set -euo pipefail
cd "$(dirname "$0")"                       # -> testbed/
TESTBED="$PWD"
REPO_ROOT="$(cd .. && pwd)"
COMPOSE="docker compose -f docker-compose.yml"
NETWORK="rpos-testbed_dnsnet"
UNBOUND_IP="172.28.0.7"
MANIFEST="dns/zones/MANIFEST.json"

# ----- defaults -------------------------------------------------------------------------------
N=8; QPS=""; DURATION=""; WARMUP=30; SEED=20260919; ALPHA=1.0
NO_NETEM=0; REGIONS=2; SAME_MS=5; CROSS_MS=50
RESOLVER=""; PORT=5300; OUTDIR="$REPO_ROOT/results"; HEALTH_TIMEOUT=180; KEEP_UP=0

# Print the leading comment banner (lines 2.. up to `set -euo`) as help text.
usage() { awk 'NR>1 && /^set -euo/{exit} NR>1{sub(/^# ?/,"");print}' "$0"; }
fail()  { echo "FAIL: $*" >&2; exit 1; }
note()  { echo "== $* =="; }

# ----- arg parsing ----------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --nodes)          N="$2"; shift 2 ;;
        --qps)            QPS="$2"; shift 2 ;;
        --duration)       DURATION="$2"; shift 2 ;;
        --warmup)         WARMUP="$2"; shift 2 ;;
        --seed)           SEED="$2"; shift 2 ;;
        --alpha)          ALPHA="$2"; shift 2 ;;
        --no-netem)       NO_NETEM=1; shift ;;
        --regions)        REGIONS="$2"; shift 2 ;;
        --same-ms)        SAME_MS="$2"; shift 2 ;;
        --cross-ms)       CROSS_MS="$2"; shift 2 ;;
        --resolver)       RESOLVER="$2"; shift 2 ;;
        --port)           PORT="$2"; shift 2 ;;
        --output-dir)     OUTDIR="$2"; shift 2 ;;
        --health-timeout) HEALTH_TIMEOUT="$2"; shift 2 ;;
        --keep-up)        KEEP_UP=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; echo "try: $0 --help" >&2; exit 2 ;;
    esac
done

# a positive-number check that works for ints and floats (qps/duration may be fractional)
is_pos() { python3 -c "import sys; sys.exit(0 if float(sys.argv[1])>0 else 1)" "$1" 2>/dev/null; }

[ -n "$QPS" ]      || fail "--qps is required (try: $0 --help)"
[ -n "$DURATION" ] || fail "--duration is required (try: $0 --help)"
is_pos "$QPS"      || fail "--qps must be a positive number (got '$QPS')"
is_pos "$DURATION" || fail "--duration must be a positive number (got '$DURATION')"
case "$N" in ''|*[!0-9]*) fail "--nodes must be a positive integer (got '$N')" ;; esac
[ "$N" -ge 1 ]     || fail "--nodes must be >= 1"

# ----- preconditions --------------------------------------------------------------------------
docker info >/dev/null 2>&1 || fail "Docker daemon not running — start Docker Desktop and retry."

# Host mode needs dnspython on the host; if absent we can still run via the in-network fallback.
HOST_PY_OK=0
if python3 -c "import dns.query" >/dev/null 2>&1; then HOST_PY_OK=1; fi

# ----- run identity / output ------------------------------------------------------------------
TS="$(date -u +%Y%m%d-%H%M%SZ)"
RUN_TAG="exp_${TS}_N${N}_q${QPS}_d${DURATION}"
mkdir -p "$OUTDIR"
CSV="$OUTDIR/${RUN_TAG}.csv"
MANIFEST_CSV="$OUTDIR/experiments.csv"
SCRATCH="$(mktemp -d)"
WARMUP_CSV="$SCRATCH/warmup.csv"

# ----- teardown trap (idempotent) -------------------------------------------------------------
NETEM_APPLIED=0
TORE_DOWN=0
teardown() {
    [ "$TORE_DOWN" -eq 1 ] && return 0
    TORE_DOWN=1
    rm -rf "$SCRATCH" 2>/dev/null || true
    if [ "$KEEP_UP" -eq 1 ]; then
        note "leaving the stack up (--keep-up); tear down with: $COMPOSE down"
        return 0
    fi
    note "tearing down"
    [ "$NETEM_APPLIED" -eq 1 ] && ./netem.sh clear >/dev/null 2>&1 || true
    $COMPOSE down >/dev/null 2>&1 || true
}
trap teardown EXIT

# ----- pick a MANIFEST domain + expected answer (for health + host probe) ---------------------
# (the manifest is created by up.sh below if missing; read it after bring-up)
read_probe_domain() {
    python3 - "$MANIFEST" <<'PY'
import json, sys
try:
    recs = json.load(open(sys.argv[1]))["records"]
except Exception:
    print("google.com 10.0.0.1"); raise SystemExit
d = "google.com" if "google.com" in recs else next(iter(recs))
print(d, recs[d]["answer_ip"])
PY
}

# ----- 1. bring up ----------------------------------------------------------------------------
note "bringing up the testbed with N=$N resolver node(s)"
./up.sh "$N"

read -r PROBE_DOMAIN PROBE_ANSWER < <(read_probe_domain)

# ----- 2. wait for health ---------------------------------------------------------------------
note "waiting for health (up to ${HEALTH_TIMEOUT}s; probe domain=$PROBE_DOMAIN)"
deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
while :; do
    healthy=$($COMPOSE ps --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -c 'node.*healthy' || true)
    innet=""
    if [ "$healthy" -ge "$N" ]; then
        innet=$($COMPOSE exec -T query-gen dig @unbound "$PROBE_DOMAIN" +short +time=3 +tries=1 2>/dev/null | head -1 || true)
    fi
    if [ "$healthy" -ge "$N" ] && [ "$innet" = "$PROBE_ANSWER" ]; then
        echo "  $healthy/$N nodes healthy; Unbound recursion OK ($PROBE_DOMAIN -> $innet)"
        break
    fi
    [ "$(date +%s)" -lt "$deadline" ] || fail "stack not healthy within ${HEALTH_TIMEOUT}s (nodes healthy=$healthy/$N, in-net answer='${innet:-<none>}')"
    sleep 3
done

# authoritative done-when print (asserts all-up + Unbound recursion)
./verify.sh "$PROBE_DOMAIN"

# ----- 3. choose resolver mode ----------------------------------------------------------------
# host mode: query_gen on the host against RESOLVER:PORT.  innet mode: query_gen inside a
# throwaway rpos-node container on dnsnet, straight at Unbound.
MODE=""
if [ -n "$RESOLVER" ]; then
    MODE="host"; note "resolver mode: host (forced --resolver $RESOLVER:$PORT)"
else
    RESOLVER="127.0.0.1"
    probe=$(dig @127.0.0.1 -p "$PORT" "$PROBE_DOMAIN" +short +time=3 +tries=1 2>/dev/null | head -1 || true)
    if [ "$probe" = "$PROBE_ANSWER" ] && [ "$HOST_PY_OK" -eq 1 ]; then
        MODE="host"; note "resolver mode: host (127.0.0.1:$PORT reachable, dnspython present)"
    else
        MODE="innet"
        if [ "$probe" != "$PROBE_ANSWER" ]; then
            note "resolver mode: in-network (host port $PORT dead: got '${probe:-<none>}' — Docker Desktop host-forward quirk)"
        else
            note "resolver mode: in-network (host dnspython missing)"
        fi
    fi
fi
[ "$MODE" = "host" ] && [ "$HOST_PY_OK" -eq 0 ] && \
    fail "host mode needs dnspython on the host (pip install dnspython), or drop --resolver to use the in-network fallback"

# run_load MODE OUTPUT SEED RESOLVER_NAME EXTRA_ARGS...
# emits a query_gen run in the selected mode; OUTPUT is a host path under $OUTDIR or $SCRATCH.
run_load() {
    local mode="$1" out="$2" seed="$3" name="$4"; shift 4
    if [ "$mode" = "host" ]; then
        python3 query_gen.py --qps "$QPS" --duration "$1" --alpha "$ALPHA" --seed "$seed" \
            --resolver "$RESOLVER" --port "$PORT" --resolver-name "$name" --output "$out"
    else
        # In-network: run query_gen inside a throwaway rpos-node container on dnsnet. Mount the
        # repo at /repo (so query_gen.py + dns/ resolve) and the OUTPUT's parent dir at /out (so
        # the CSV lands on the host regardless of where $out lives — scratch or an out-dir
        # outside the repo). Both must be Docker Desktop file-sharing paths.
        local out_dir out_base
        out_dir="$(cd "$(dirname "$out")" && pwd)"; out_base="$(basename "$out")"
        docker run --rm --network "$NETWORK" \
            -v "$REPO_ROOT":/repo -v "$out_dir":/out -w /repo/testbed \
            rpos-node:latest \
            python query_gen.py --qps "$QPS" --duration "$1" --alpha "$ALPHA" --seed "$seed" \
                --resolver "$UNBOUND_IP" --port 53 --resolver-name "$name" --output "/out/$out_base"
    fi
}

# ----- 4. netem -------------------------------------------------------------------------------
if [ "$NO_NETEM" -eq 1 ]; then
    note "skipping tc netem (--no-netem)"
else
    note "applying tc netem link delays (regions=$REGIONS same=${SAME_MS}ms cross=${CROSS_MS}ms)"
    REGIONS="$REGIONS" SAME_MS="$SAME_MS" CROSS_MS="$CROSS_MS" NETWORK="$NETWORK" ./netem.sh apply
    NETEM_APPLIED=1
fi

# ----- 5. warm-up (real query load, discarded) ------------------------------------------------
if is_pos "$WARMUP"; then
    note "warm-up: ${WARMUP}s of query load (populating Unbound's cache; CSV discarded)"
    run_load "$MODE" "$WARMUP_CSV" "$((SEED + 1))" "unbound-warmup" "$WARMUP" || true
else
    note "skipping warm-up (--warmup $WARMUP)"
fi

# ----- 6. measured run ------------------------------------------------------------------------
note "measured run: ${QPS} qps for ${DURATION}s -> $CSV"
run_load "$MODE" "$CSV" "$SEED" "unbound-$MODE" "$DURATION"

# ----- 7. summary -----------------------------------------------------------------------------
note "summary"
python3 - "$CSV" "$MANIFEST_CSV" "$RUN_TAG" "$N" "$QPS" "$DURATION" "$WARMUP" "$SEED" "$MODE" "$NETEM_APPLIED" "$REPO_ROOT" <<'PY'
import csv, os, statistics, sys
csv_path, manifest, tag, n, qps, dur, warmup, seed, mode, netem, repo = sys.argv[1:12]

lat_ok, rows, ok = [], 0, 0
with open(csv_path) as f:
    for r in csv.DictReader(f):
        rows += 1
        if r["success"] == "True":
            ok += 1
            try: lat_ok.append(float(r["latency_ms"]))
            except ValueError: pass

def pct(vals, p):
    if not vals: return float("nan")
    if len(vals) == 1: return vals[0]
    return statistics.quantiles(vals, n=100, method="inclusive")[p - 1]

rate    = 100.0 * ok / rows if rows else 0.0
ach_qps = rows / float(dur) if float(dur) else 0.0
p50, p95, p99 = (pct(lat_ok, p) for p in (50, 95, 99))
netem_on = "on" if netem == "1" else "off"
rel = os.path.relpath(csv_path, repo)

print(f"[run_experiment] N={n} qps={qps} dur={dur} netem={netem_on} mode={mode} "
      f"rows={rows} ok={ok} ({rate:.1f}%) ach={ach_qps:.1f}qps "
      f"p50={p50:.1f} p95={p95:.1f} p99={p99:.1f} ms -> {rel}")

# append a manifest row (create header if absent) for Phase 6 aggregation
header = ["run_tag","nodes","qps","duration","warmup","seed","mode","netem",
          "rows","ok","success_rate_pct","achieved_qps","p50_ms","p95_ms","p99_ms","csv"]
new = not os.path.exists(manifest)
with open(manifest, "a", newline="") as f:
    w = csv.writer(f)
    if new: w.writerow(header)
    w.writerow([tag, n, qps, dur, warmup, seed, mode, netem_on, rows, ok,
                f"{rate:.2f}", f"{ach_qps:.3f}", f"{p50:.3f}", f"{p95:.3f}", f"{p99:.3f}", rel])
PY

# teardown runs via the EXIT trap
