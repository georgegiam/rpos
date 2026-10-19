#!/usr/bin/env bash
# Issue #51 [C2] — Response timeout δ under realistic network jitter (Phase 8, examiner point (i)).
#
# C2 answers the money question left open by Phase 1 and sharpened by C1: "what δ separates honest
# from cheater WITHOUT rejecting honest provers under real network conditions?" It layers the frozen
# netem jitter model (base RTT = 2×one-way = 10 ms intra / 100 ms cross + Gaussian σ∈{5,10,20} ms)
# onto two response-time populations and reports, across δ∈{1,2,3,5,10}s:
#   * false-reject  = P(an HONEST prover misses δ)  — honest = base RTT + a real (measured here)
#                     prove_v3+verify_v3 proof + jitter; network-bound, FR≈0.
#   * false-accept  = P(a CHEATER keeping ρ% labels answers within δ) — t_rec(ρ) read from C1's
#                     committed trade-off (results/C1_retention_attack.csv, thesis N).
# Deliverables: results/C2_delta_jitter.csv + results/fig_C2_roc.png (ROC) + results/C2_NOTES.md.
#
# LIKE A7/B2/B5/C1 THIS IS A MICROBENCHMARK, NOT A DOCKER TESTBED RUN (and needs no Docker): the
# honest proof cost is a property of the PoSpace plot graph (measured in-process over the frozen
# prove_v3/verify_v3), and the netem delays enter as model parameters. It IMPORTS the frozen phase1
# primitives and READS C1's committed CSV; rpos/rpos.py and all of phase1/* and node/* stay
# byte-identical (CLAUDE.md §2). Fixed seed 20260919.
#
# DEPENDS ON C1: run `bash experiments/run_c1.sh` first so results/C1_retention_attack.csv exists.
#
# Usage:
#   bash experiments/run_c2.sh                                   # full sweep -> CSV + PNG + NOTES numbers
#   C2_NO_PLOT=1 bash experiments/run_c2.sh                      # table only
#   C2_SIGMAS="5,10,20" C2_DELTAS="1,2,3,5,10" C2_INDEGREES="2" bash experiments/run_c2.sh
#   C2_SKIP_SELFTEST=1 bash experiments/run_c2.sh               # skip the pre-run self-test
#
# Requires: python3 with matplotlib + numpy (same env as the other experiments). NO Docker.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

# knobs (env-overridable for smoke runs) — forwarded to c2_delta_jitter.py
SIGMAS="${C2_SIGMAS:-5,10,20}"
DELTAS="${C2_DELTAS:-1,2,3,5,10}"
INDEGREES="${C2_INDEGREES:-2,4,8}"

args=( --sigmas "$SIGMAS" --deltas "$DELTAS" --indegrees "$INDEGREES" )
[ "${C2_NO_PLOT:-0}" = "1" ] && args+=( --no-plot )

cd "$REPO_ROOT"
if [ "${C2_SKIP_SELFTEST:-0}" != "1" ]; then
  echo "== [C2] self-test (deterministic, no Docker) =="
  python3 "$HERE/c2_delta_jitter.py" --self-test
fi

echo "== [C2] δ under network jitter (no Docker) =="
echo "== [C2] sigmas=$SIGMAS deltas=$DELTAS indegrees=$INDEGREES =="
exec python3 "$HERE/c2_delta_jitter.py" "${args[@]}"
