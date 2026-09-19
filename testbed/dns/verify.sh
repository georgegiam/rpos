#!/usr/bin/env bash
# Issue #18 [P3-1] — prove the done-when: `dig` returns an ANSWER, via the real referral chain
# root -> TLD -> authoritative. Reads a real domain + its expected auth/answer from
# zones/MANIFEST.json (measure, don't assert) and checks each tier. Exits non-zero on mismatch.
#
# Usage:  ./verify.sh [domain]   (defaults to google.com, else the first manifest record)
# Requires: dig (host) + the tier running (`docker compose -f docker-compose.dns.yml up -d`).
set -euo pipefail
cd "$(dirname "$0")"

MANIFEST=zones/MANIFEST.json
[ -f "$MANIFEST" ] || { echo "FAIL: $MANIFEST missing — run generate_zones.py first"; exit 1; }

read -r DOMAIN TLD AUTH ANSWER_IP < <(python3 - "${1:-}" <<'PY'
import json, sys
m = json.load(open("zones/MANIFEST.json"))
recs = m["records"]
d = sys.argv[1] if len(sys.argv) > 1 else ""
if not d or d not in recs:
    d = "google.com" if "google.com" in recs else next(iter(recs))
r = recs[d]
print(d, r["tld"], r["auth"], r["answer_ip"])
PY
)

# host published ports (see docker-compose.dns.yml)
ROOT_PORT=5301
case "$TLD" in com) TLD_PORT=5302 ;; org) TLD_PORT=5303 ;; *) echo "FAIL: unknown TLD $TLD"; exit 1 ;; esac
case "$AUTH" in auth1) AUTH_PORT=5304 ;; auth2) AUTH_PORT=5305 ;; *) echo "FAIL: unknown auth $AUTH"; exit 1 ;; esac

echo "== verifying $DOMAIN  (tld=$TLD auth=$AUTH expected A=$ANSWER_IP) =="
fail() { echo "FAIL: $1"; echo "----- dig output -----"; echo "$2"; exit 1; }

# 1) root -> referral to the TLD (no ANSWER; AUTHORITY carries the TLD NS)
OUT=$(dig @127.0.0.1 -p "$ROOT_PORT" "$DOMAIN" +norecurse +tries=1 +time=3)
echo "$OUT" | grep -q "status: NOERROR" || fail "root: status not NOERROR" "$OUT"
echo "$OUT" | grep -q "ANSWER: 0," || fail "root: expected a referral (0 answers)" "$OUT"
echo "$OUT" | awk '/AUTHORITY SECTION/{f=1} f' | grep -qiE "$TLD\.\s+.*NS" || fail "root: no $TLD delegation in AUTHORITY" "$OUT"
echo "  [1/3] root -> $TLD referral OK"

# 2) TLD -> referral to the domain's authoritative server (glue -> auth IP)
OUT=$(dig @127.0.0.1 -p "$TLD_PORT" "$DOMAIN" +norecurse +tries=1 +time=3)
echo "$OUT" | grep -q "status: NOERROR" || fail "$TLD: status not NOERROR" "$OUT"
echo "$OUT" | grep -q "ANSWER: 0," || fail "$TLD: expected a referral (0 answers)" "$OUT"
echo "$OUT" | awk '/AUTHORITY SECTION/{f=1} f' | grep -qi "ns1.$DOMAIN" || fail "$TLD: no ns1.$DOMAIN delegation" "$OUT"
echo "  [2/3] $TLD -> $AUTH referral OK"

# 3) authoritative server -> ANSWER (aa flag + exact A record) === DONE-WHEN ===
OUT=$(dig @127.0.0.1 -p "$AUTH_PORT" "$DOMAIN" +norecurse +tries=1 +time=3)
echo "$OUT" | grep -q "status: NOERROR" || fail "$AUTH: status not NOERROR" "$OUT"
echo "$OUT" | grep -qE "flags:[^;]* aa" || fail "$AUTH: not authoritative (no aa flag)" "$OUT"
echo "$OUT" | awk '/ANSWER SECTION/{f=1} f' | grep -qE "IN\s+A\s+$ANSWER_IP\b" || fail "$AUTH: expected A $ANSWER_IP" "$OUT"
echo "  [3/3] $AUTH answers $DOMAIN A $ANSWER_IP  (aa=1)  === DONE-WHEN met ==="

echo "== PASS =="
