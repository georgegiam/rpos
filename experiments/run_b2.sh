#!/usr/bin/env bash
# Issue #43 [B2] — Targeted chunk-majority capture / ID grinding (Phase 7, examiner point (ii)).
#
# B2 answers: can an adversary capture a majority of a target domain's s=3 replicas, and what does
# it COST for random vs targeted placement? And can node IDs be GROUND (pk -> id) onto a chosen
# chunk's replica slots? The answer the code gives: node_id = SHA-256(pk) is unsalted and the
# attacker picks its own pk, so landing in one inter-node gap (width ~2^160/N) takes ~N hashes
# (trivially cheap at every scale); the ONLY real cost is the PoSpace plot the winning pk must
# carry. So TARGETED capture of any chosen chunk costs a CONSTANT ceil((s+1)/2)=2 plotted
# identities (1 under B1's measured >=1-of-s vote weakness), while RANDOM placement needs ~O(N)
# identities to hit a chosen target. PoSpace rate-limits the NUMBER of identities, not WHERE
# they land.
#
# UNLIKE A1-A6 AND LIKE A7, THIS IS A MICROBENCHMARK, NOT A DOCKER TESTBED RUN (and needs no
# Docker): "hashes to grind a pk" is a pure, verifier-reproducible computation. B2 reuses the exact
# host-side ring + replica toolkit from experiments/b1_placement.py (the converged-ring model the
# node, the sims and B1 share) and node/ids.py, and additionally proves the grind->admission->
# capture chain on a REAL in-process PoSpace ring (source=admission_inproc, the A7 pattern). B1
# already DEMONSTRATED targeted placement forging google.com at 100% on the live N=32 ring; B2
# measures the COST of achieving that placement. See results/B2_NOTES.md for the full rationale.
#
# New code in a new file (CLAUDE.md §2): imports/reads only — rpos/rpos.py, node/chord.py,
# node/storage.py, node/ledger.py, node/pospace_admission.py, node/net.py, phase1/pospace_drg.py
# and experiments/b1_placement.py stay byte-identical.
#
# Frozen B2 workload (PARAMETERS.md): N=32 real ring, s=3, grind-scale sweep {32, 1e3, 1e6, 1e9}
# (empirical to 1e6, geometric expectation at 1e9), capture probabilities {.5, .9, .99}, seed
# 20260919, in-process PoSpace demo ring N=8 at plot 2^10.
#
# Usage:
#   bash experiments/run_b2.sh                              # self-test, then full analysis -> CSV+PNG
#   B2_NO_DEMO=1 bash experiments/run_b2.sh                 # skip the in-process admission demo
#   B2_SCALE="32,1000" bash experiments/run_b2.sh           # quick grind-scale subset
#   B2_SKIP_SELFTEST=1 bash experiments/run_b2.sh           # analysis only
#
# Requires: python3 (the 3.11 experiment env) with matplotlib; the in-process demo also needs
# dnspython (it is skipped with a clear note if absent). NO Docker.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

SCALE="${B2_SCALE:-32,1000,1000000,1000000000}"
SEED="${B2_SEED:-20260919}"

args=( --scale "$SCALE" --seed "$SEED" )
[ "${B2_NO_DEMO:-0}" = "1" ] && args+=( --no-demo )
[ "${B2_NO_PLOT:-0}" = "1" ] && args+=( --no-plot )

cd "$REPO_ROOT"

if [ "${B2_SKIP_SELFTEST:-0}" != "1" ]; then
    echo "== [B2] self-test (deterministic, no Docker) =="
    python3 "$HERE/b2_grinding.py" --self-test
fi

echo "== [B2] grinding / capture-cost analysis (no Docker) — scale=$SCALE seed=$SEED =="
exec python3 "$HERE/b2_grinding.py" "${args[@]}"
