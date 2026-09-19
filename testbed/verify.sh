#!/usr/bin/env bash
# Issue #19 [P3-2] — prove the done-when for the full testbed:
#   1. every container is Up and every resolver node is healthy;
#   2. Unbound recursively resolves a real MANIFEST domain end-to-end over the #18 hierarchy
#      (root -> TLD -> authoritative), returning the exact expected A record.
#
# The recursion check runs from INSIDE the network (via the query-gen dig box) so it is
# platform-independent; the host-port path (macOS convenience) is checked too but is not fatal.
#
# Usage:  ./verify.sh [domain]   (defaults to a domain read from zones/MANIFEST.json)
# Requires: the testbed running (`./up.sh N`).
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.yml"
MANIFEST=dns/zones/MANIFEST.json
[ -f "$MANIFEST" ] || { echo "FAIL: $MANIFEST missing — run ./up.sh first"; exit 1; }

# pick a domain + its expected answer IP from the manifest
read -r DOMAIN EXPECT < <(python3 - "${1:-}" <<'PY'
import json, sys
recs = json.load(open("dns/zones/MANIFEST.json"))["records"]
d = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else ""
if not d or d not in recs:
    d = "google.com" if "google.com" in recs else next(iter(recs))
print(d, recs[d]["answer_ip"])
PY
)
echo "== verifying testbed (domain=$DOMAIN expected A=$EXPECT) =="
fail() { echo "FAIL: $1"; exit 1; }

# 1) every service Up; every node healthy
NOT_UP=$($COMPOSE ps -a --format '{{.Name}} {{.State}}' | awk '$2!="running"{print $1}')
[ -z "$NOT_UP" ] || fail "not all containers running: $NOT_UP"
NODES=$($COMPOSE ps --format '{{.Name}} {{.Status}}' | grep -c 'node.*healthy' || true)
[ "$NODES" -ge 1 ] || fail "no healthy resolver nodes"
echo "  [1/2] $($COMPOSE ps -q | wc -l | tr -d ' ') containers Up; $NODES node(s) healthy"

# 2) Unbound recursion, in-network (authoritative check)
GOT=$($COMPOSE exec -T query-gen dig @unbound "$DOMAIN" +short +time=5 +tries=2 | head -1)
[ "$GOT" = "$EXPECT" ] || fail "in-network: Unbound returned '$GOT', expected '$EXPECT'"
echo "  [2/2] in-network: dig @unbound $DOMAIN -> $GOT  (recursed root->TLD->auth)  === DONE-WHEN met ==="

# host-port path (macOS convenience; non-fatal if the platform's UDP forwarding misbehaves)
HGOT=$(dig @127.0.0.1 -p 5300 "$DOMAIN" +short +time=3 +tries=1 2>/dev/null | head -1 || true)
if [ "$HGOT" = "$EXPECT" ]; then
    echo "        host port 5300 also OK ($HGOT)"
else
    echo "        note: host-port dig returned '${HGOT:-<none>}' (Docker Desktop host-forward quirk; in-network check is authoritative)"
fi

echo "== PASS =="
