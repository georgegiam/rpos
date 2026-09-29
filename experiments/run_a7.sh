#!/usr/bin/env bash
# Issue #38 [A7] — Admission: join time vs plot size (Phase 6, examiner point (iii)).
#
# A7 measures the cost of JOINING the ring and how it scales with the PoSpace plot size — the
# admission cost the thesis never measured end-to-end. It holds the ring at N=8 and sweeps the plot
# size over {2^10, 2^12, 2^14, 2^16} leaves (the frozen v3 DRG scheme, phase1/pospace_drg.py), with
# delta=2 (the node default) as the headline plus a delta in {2,4,8} in-degree secondary axis, and
# reports the plot-generation / Merkle-commit / challenge decomposition of admission.
#
# UNLIKE A1-A6 THIS IS A MICROBENCHMARK, NOT A DOCKER TESTBED RUN (and needs no Docker). At these
# sizes a plot takes ~1.6 ms (2^10) to ~105 ms (2^16); a real N=8 container ring would bury that
# ~100 ms plot-size signal under seconds of container-startup / ring-convergence noise. A7 instead
# times the node's EXACT admission code (node/pospace_admission.py: plot_v3 + commit_v3 + a
# prove_v3/verify_v3 challenge), imported the same way the node imports it, over the 8 real ring keys
# (_pk_for(0..7)) [source=component], and cross-checks it against a REAL in-process 8-node
# create()/join() ring [source=ring_inproc]. See results/A7_NOTES.md for the full rationale + caveats.
#
# New code in a new file (CLAUDE.md §2): imports/reads only — rpos.py, node/chord.py, node/ledger.py,
# node/storage.py, phase1/pospace_drg.py and node/pospace_admission.py stay byte-identical.
#
# Frozen A7 workload (PARAMETERS.md): N=8, plot sizes {2^10,2^12,2^14,2^16}, delta headline 2 /
# secondary {2,4,8}, seed 20260919, 5 component repeats x 8 keys, 3 in-process-ring repeats.
#
# Usage:
#   bash experiments/run_a7.sh                                   # full sweep -> CSV + PNG + NOTES numbers
#   A7_SIZES="1024,4096" A7_REPEATS=1 bash experiments/run_a7.sh # quick smoke subset
#   A7_COMPONENT_ONLY=1 bash experiments/run_a7.sh               # skip the in-process ring cross-check
#
# Requires: python3 with matplotlib (same env as the other experiments). NO Docker.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

# knobs (env-overridable for smoke runs) — forwarded to a7_admission.py
SIZES="${A7_SIZES:-1024,4096,16384,65536}"
DELTAS="${A7_DELTAS:-2,4,8}"
REPEATS="${A7_REPEATS:-5}"
CHALLENGES="${A7_CHALLENGES:-30}"

args=( --sizes "$SIZES" --deltas "$DELTAS" --repeats "$REPEATS" --challenges "$CHALLENGES" )
[ "${A7_COMPONENT_ONLY:-0}" = "1" ] && args+=( --component-only )
[ "${A7_NO_PLOT:-0}" = "1" ]        && args+=( --no-plot )

echo "== [A7] admission join-time vs plot-size microbenchmark (no Docker) =="
echo "== [A7] sizes=$SIZES deltas=$DELTAS repeats=$REPEATS challenges=$CHALLENGES =="
cd "$REPO_ROOT"
exec python3 "$HERE/a7_admission.py" "${args[@]}"
