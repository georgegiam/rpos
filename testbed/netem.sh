#!/usr/bin/env bash
# Issue #20 [P3-3] — tc netem inter-container link delays for the Phase 3 testbed.
#
# Emulates a two-tier network over the testbed's bridge (rpos-testbed_dnsnet): SAME_MS within a
# region, CROSS_MS across regions. Containers are assigned to regions BY INDEX (deterministic:
# sorted by IP, region = index % REGIONS), so the assignment is reproducible for a given running
# set (CLAUDE.md §2). Without this every container-to-container hop is ~0ms and the Phase 6
# latency/throughput numbers (and the Unbound baseline) would be meaningless.
#
# HOW (no image/compose edits — CLAUDE.md §2): tc runs inside each target container's network
# namespace via a throwaway helper container that shares the netns and holds NET_ADMIN:
#   docker run --rm --net=container:<id> --cap-add=NET_ADMIN rpos-netem tc ...
# so the #19 node/unbound images and the #18 DNS tier stay byte-identical (see netem-helper/).
#
# DELAY UNITS: SAME_MS/CROSS_MS are ONE-WAY egress delays applied at BOTH endpoints, so the
# ping RTT a link shows is ~2x the number (same-region ~10ms, cross-region ~100ms). `verify`
# asserts that.
#
# PER-DESTINATION delays need a classful qdisc (a single netem can't vary by destination):
#   root  prio bands 3, priomap -> all UNMATCHED traffic to band 3 (class 1:3, NO delay, so the
#         gateway/host path is untouched)
#   1:1   netem delay SAME_MS    1:2   netem delay CROSS_MS
#   u32 filters: each same-region peer IP -> 1:1 ; each cross-region peer IP -> 1:2
#
# Usage:
#   ./netem.sh [apply]     build helper if needed, assign regions, program tc in every container
#   ./netem.sh verify      ping a same- and a cross-region peer; assert RTT ~= 2x (done-when)
#   ./netem.sh clear       remove the netem qdiscs from every container
#   ./netem.sh show        dump each container's current qdisc + filters
#
# Config (env): SAME_MS=5  CROSS_MS=50  REGIONS=2  NETWORK=rpos-testbed_dnsnet  IFACE=eth0
#               HELPER_IMG=rpos-netem:latest  PING_COUNT=10
# Requires: the testbed running (`./up.sh N`).
set -euo pipefail
cd "$(dirname "$0")"

SAME_MS="${SAME_MS:-5}"
CROSS_MS="${CROSS_MS:-50}"
REGIONS="${REGIONS:-2}"
NETWORK="${NETWORK:-rpos-testbed_dnsnet}"
IFACE="${IFACE:-eth0}"
HELPER_IMG="${HELPER_IMG:-rpos-netem:latest}"
PING_COUNT="${PING_COUNT:-10}"

fail() { echo "FAIL: $1" >&2; exit 1; }

# Parallel arrays for the discovered members, sorted by IP, with region = index % REGIONS.
IDS=(); NAMES=(); IPS=(); REGS=()

# Build the helper image if it is not present (idempotent).
ensure_helper() {
    if ! docker image inspect "$HELPER_IMG" >/dev/null 2>&1; then
        echo "== building helper image $HELPER_IMG =="
        docker build -t "$HELPER_IMG" netem-helper
    fi
}

# Populate IDS/NAMES/IPS/REGS from `docker network inspect`, sorted by numeric IP.
discover() {
    local line
    while IFS=$'\t' read -r id name ip reg; do
        [ -n "$id" ] || continue
        IDS+=("$id"); NAMES+=("$name"); IPS+=("$ip"); REGS+=("$reg")
    done < <(python3 - "$NETWORK" "$REGIONS" <<'PY'
import json, subprocess, sys
network, regions = sys.argv[1], int(sys.argv[2])
out = subprocess.run(["docker", "network", "inspect", network],
                     capture_output=True, text=True)
if out.returncode != 0:
    sys.stderr.write(out.stderr)
    sys.exit(1)
conts = json.loads(out.stdout)[0].get("Containers", {})
members = []
for cid, c in conts.items():
    ip = (c.get("IPv4Address") or "").split("/")[0]
    if ip:
        members.append((tuple(int(o) for o in ip.split(".")), cid, c.get("Name", ""), ip))
members.sort()  # deterministic: by numeric IP
for idx, (_key, cid, name, ip) in enumerate(members):
    print(f"{cid}\t{name}\t{ip}\t{idx % regions}")
PY
    )
    [ "${#IDS[@]}" -gt 0 ] || fail "no containers found on network '$NETWORK' — is the testbed up (./up.sh N)?"
}

print_assignment() {
    echo "== region assignment (SAME=${SAME_MS}ms in-region, CROSS=${CROSS_MS}ms cross-region; REGIONS=$REGIONS) =="
    printf '  %-22s %-16s %s\n' "CONTAINER" "IP" "REGION"
    local i
    for i in "${!IDS[@]}"; do
        printf '  %-22s %-16s %s\n' "${NAMES[$i]}" "${IPS[$i]}" "${REGS[$i]}"
    done
}

# Program tc inside container index $1 (runs the helper in that container's netns).
apply_one() {
    local i="$1" j same_ips="" cross_ips=""
    for j in "${!IDS[@]}"; do
        [ "$j" = "$i" ] && continue
        if [ "${REGS[$j]}" = "${REGS[$i]}" ]; then
            same_ips+=" ${IPS[$j]}"
        else
            cross_ips+=" ${IPS[$j]}"
        fi
    done

    # tc script executed inside the target's netns. band 3 (class 1:3) keeps its default fifo =>
    # no delay for anything not matched below (gateway, host, self).
    local script="set -e
tc qdisc del dev $IFACE root 2>/dev/null || true
tc qdisc add dev $IFACE root handle 1: prio bands 3 priomap 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2
tc qdisc add dev $IFACE parent 1:1 handle 10: netem delay ${SAME_MS}ms
tc qdisc add dev $IFACE parent 1:2 handle 20: netem delay ${CROSS_MS}ms
for ip in${same_ips:- }; do tc filter add dev $IFACE protocol ip parent 1:0 prio 1 u32 match ip dst \$ip/32 flowid 1:1; done
for ip in${cross_ips:- }; do tc filter add dev $IFACE protocol ip parent 1:0 prio 1 u32 match ip dst \$ip/32 flowid 1:2; done"

    docker run --rm --net="container:${IDS[$i]}" --cap-add=NET_ADMIN "$HELPER_IMG" \
        sh -c "$script" >/dev/null
    local n_same n_cross; n_same=$(set -- $same_ips; echo $#); n_cross=$(set -- $cross_ips; echo $#)
    printf '  %-22s region %s  (same:%s cross:%s)\n' "${NAMES[$i]}" "${REGS[$i]}" "$n_same" "$n_cross"
}

clear_one() {
    docker run --rm --net="container:${IDS[$1]}" --cap-add=NET_ADMIN "$HELPER_IMG" \
        sh -c "tc qdisc del dev $IFACE root 2>/dev/null || true" >/dev/null
}

# ping $2 (an IP) from inside container index $1's netns; echo the average RTT in ms.
ping_avg() {
    local out
    out=$(docker run --rm --net="container:${IDS[$1]}" --cap-add=NET_RAW "$HELPER_IMG" \
          ping -c "$PING_COUNT" -i 0.2 -W 2 "$2" 2>/dev/null || true)
    python3 - <<PY
import re, sys
m = re.search(r"min/avg/max\S*\s*=\s*[\d.]+/([\d.]+)/", """$out""")
print(m.group(1) if m else "")
PY
}

cmd_apply() {
    ensure_helper
    discover
    print_assignment
    echo "== applying tc netem to ${#IDS[@]} container(s) =="
    local i
    for i in "${!IDS[@]}"; do apply_one "$i"; done
    echo "== done — verify with: ./netem.sh verify =="
}

cmd_clear() {
    ensure_helper
    discover
    echo "== clearing tc netem from ${#IDS[@]} container(s) =="
    local i
    for i in "${!IDS[@]}"; do clear_one "$i"; echo "  ${NAMES[$i]} cleared"; done
    echo "== done =="
}

cmd_show() {
    ensure_helper
    discover
    local i
    for i in "${!IDS[@]}"; do
        echo "== ${NAMES[$i]} (${IPS[$i]}, region ${REGS[$i]}) =="
        docker run --rm --net="container:${IDS[$i]}" --cap-add=NET_ADMIN "$HELPER_IMG" \
            sh -c "tc qdisc show dev $IFACE; echo '  --- filters ---'; tc filter show dev $IFACE" \
            2>/dev/null | sed 's/^/  /'
    done
}

cmd_verify() {
    ensure_helper
    discover

    # Find a source container that has BOTH a same-region and a cross-region peer.
    local i j src=-1 same_peer="" cross_peer="" have_same have_cross
    for i in "${!IDS[@]}"; do
        have_same=""; have_cross=""
        for j in "${!IDS[@]}"; do
            [ "$j" = "$i" ] && continue
            if [ "${REGS[$j]}" = "${REGS[$i]}" ]; then have_same="${IPS[$j]}"
            else have_cross="${IPS[$j]}"; fi
        done
        if [ -n "$have_same" ] && [ -n "$have_cross" ]; then
            src="$i"; same_peer="$have_same"; cross_peer="$have_cross"; break
        fi
    done
    [ "$src" -ge 0 ] || fail "need a container with both a same-region and a cross-region peer (REGIONS=$REGIONS, ${#IDS[@]} containers) — raise N or REGIONS"

    echo "== verifying from ${NAMES[$src]} (region ${REGS[$src]}) =="
    local same_rtt cross_rtt
    same_rtt=$(ping_avg "$src" "$same_peer")
    cross_rtt=$(ping_avg "$src" "$cross_peer")
    [ -n "$same_rtt" ]  || fail "no RTT to same-region peer $same_peer (ping failed)"
    [ -n "$cross_rtt" ] || fail "no RTT to cross-region peer $cross_peer (ping failed)"
    echo "  same-region  -> $same_peer : ${same_rtt} ms  (expect ~$((2*SAME_MS)) ms)"
    echo "  cross-region -> $cross_peer : ${cross_rtt} ms  (expect ~$((2*CROSS_MS)) ms)"

    # Assert with generous tolerance bands and clear separation (one-way delay => RTT ~= 2x).
    python3 - "$same_rtt" "$cross_rtt" "$SAME_MS" "$CROSS_MS" <<'PY' || fail "RTTs do not reflect the configured delays"
import sys
same, cross, same_ms, cross_ms = (float(sys.argv[1]), float(sys.argv[2]),
                                  float(sys.argv[3]), float(sys.argv[4]))
exp_same, exp_cross = 2*same_ms, 2*cross_ms
ok = True
if not (0.6*exp_same <= same <= 3.0*exp_same + 5):
    print(f"  same-region RTT {same} ms outside [{0.6*exp_same:.1f}, {3.0*exp_same+5:.1f}]"); ok = False
if not (0.6*exp_cross <= cross <= 2.5*exp_cross):
    print(f"  cross-region RTT {cross} ms outside [{0.6*exp_cross:.1f}, {2.5*exp_cross:.1f}]"); ok = False
if not (cross > same + 0.5*(exp_cross - exp_same)):
    print(f"  cross-region ({cross} ms) not clearly > same-region ({same} ms)"); ok = False
sys.exit(0 if ok else 1)
PY
    echo "== PASS — ping RTT reflects the configured delays (done-when met) =="
}

case "${1:-apply}" in
    apply)  cmd_apply  ;;
    clear)  cmd_clear  ;;
    verify) cmd_verify ;;
    show)   cmd_show   ;;
    *) echo "usage: $0 {apply|verify|clear|show}" >&2; exit 2 ;;
esac
