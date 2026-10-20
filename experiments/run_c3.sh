#!/usr/bin/env bash
# Issue #52 [C3] — Detection probability vs challenges per round (Phase 8, examiner point (i)).
#
# C3 answers the operational follow-up to C1/C2: "how many periodic challenges does it take to catch a
# cheater with high probability?" For a cheater keeping label-fraction ρ it derives the per-challenge
# failure probability p_fail(ρ) and the detection / eviction probability after c challenges:
#   * p_fail (EMPIRICAL, time-gated)  = fraction of random challenges whose DRG back-cone recompute at
#       thesis N exceeds the response timeout δ (reuses C1's back-cone physics; φ_i > φ*=δ·rate/N).
#   * p_fail (ANALYTICAL, coverage)   = 1 − ρ^(1+avg_indegree) — the naive "any opened hole = catch"
#       upper bound; the GAP to the empirical curve is the cheater's cheap holes (recompute ≤ δ).
#   * P_detect(c) = 1 − (1−p_fail)^c   (≥1 failed challenge)  and
#   * P_evict(c)                       = run of MAX_FAILS=3 consecutive fails (the node's real policy),
#       with expected challenges / wall-clock to eviction (~5 s challenge period).
# Deliverables: results/C3_detection.csv + results/fig_C3_detection.png + results/C3_NOTES.md.
#
# LIKE A7/B2/B5/C1/C2 THIS IS A MICROBENCHMARK, NOT A DOCKER TESTBED RUN (and needs no Docker): the
# back-cone is a property of the frozen DRG graph (traversed in-process via the frozen backcone_mask),
# and the eviction curve is exact probability from the node's policy constants. It IMPORTS the frozen
# phase1 primitives and READS node/pospace_admission (REAL_PLOT_N, MAX_FAILS); rpos/rpos.py and all of
# phase1/* and node/* stay byte-identical (CLAUDE.md §2). Fixed seed 20260919.
#
# Usage:
#   bash experiments/run_c3.sh                                   # full sweep -> CSV + PNG + NOTES numbers
#   C3_QUICK=1 bash experiments/run_c3.sh                        # drop N=2^22 (fast iteration)
#   C3_NO_PLOT=1 bash experiments/run_c3.sh                      # table only
#   C3_FRACTIONS="50,25,10" C3_INDEGREES="2" C3_CHALLENGES="2000" bash experiments/run_c3.sh
#   C3_SKIP_SELFTEST=1 bash experiments/run_c3.sh               # skip the pre-run self-test
#
# Requires: python3 with numpy + matplotlib (same env as the other experiments). NO Docker.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

# knobs (env-overridable for smoke runs) — forwarded to c3_detection.py
FRACTIONS="${C3_FRACTIONS:-50,33,30,25,20,10}"
INDEGREES="${C3_INDEGREES:-2,4,8}"

args=( --fractions "$FRACTIONS" --indegrees "$INDEGREES" )
[ -n "${C3_CHALLENGES:-}" ] && args+=( --challenges "$C3_CHALLENGES" )
[ "${C3_QUICK:-0}" = "1" ] && args+=( --quick )
[ "${C3_NO_PLOT:-0}" = "1" ] && args+=( --no-plot )

cd "$REPO_ROOT"
if [ "${C3_SKIP_SELFTEST:-0}" != "1" ]; then
  echo "== [C3] self-test (deterministic, no Docker) =="
  python3 "$HERE/c3_detection.py" --self-test
fi

echo "== [C3] detection vs challenges per round (no Docker) =="
echo "== [C3] fractions=$FRACTIONS indegrees=$INDEGREES =="
exec python3 "$HERE/c3_detection.py" "${args[@]}"
