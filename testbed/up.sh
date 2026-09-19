#!/usr/bin/env bash
# Issue #19 [P3-2] — one-command bring-up of the full testbed.
#
# Usage:  ./up.sh [N]      N = resolver-node count (default 8)
#
# Ensures the (git-ignored) DNS zones exist, then builds and starts the whole world on one
# isolated network: the #18 DNS hierarchy + Unbound + N rpos nodes + the query-gen box.
# Tear down with:  docker compose -f docker-compose.yml down
set -euo pipefail
cd "$(dirname "$0")"

N="${1:-8}"

# Zones are deterministic and git-ignored — regenerate if missing (matches #18's workflow).
if [ ! -f dns/zones/MANIFEST.json ]; then
    echo "== zones/MANIFEST.json missing — generating (deterministic, --count 1000) =="
    python3 dns/generate_zones.py --count 1000
fi

echo "== bringing up testbed with $N resolver node(s) =="
docker compose -f docker-compose.yml up -d --build --scale node="$N"

echo "== container status =="
docker compose -f docker-compose.yml ps
