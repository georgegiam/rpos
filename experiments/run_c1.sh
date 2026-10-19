#!/usr/bin/env bash
# Issue #50 [C1] — Final partial-storage (retention) attack on the frozen v3 DRG scheme
# (Phase 8, examiner point (i)).
#
# C1 produces the DEFINITIVE time-space trade-off for the PROPOSED scheme: "how much storage can a
# cheater discard and still respond within the timeout?" It re-runs the Phase 1 retention attack on
# the frozen v3 DRG (phase1/pospace_drg.py + phase1/drg.py), sweeps the fraction of plot labels the
# cheater keeps {1,5,10,25,50,75,100}%, measures the DRG back-cone recompute (hash count, native
# wall-clock at 20.36 MH/s, success vs the response timeout delta) per fraction, and extrapolates to
# thesis scale N = 3,355,443,200 using the validated back-cone fraction phi.
#
# LIKE A7/B2/B5 THIS IS A MICROBENCHMARK, NOT A DOCKER TESTBED RUN (and needs no Docker): the
# retention attack is a property of the PoSpace plot graph, not the DNS ring. It IMPORTS the frozen
# phase1 primitives (attack_v3_retain.py back-cone closure, pospace_drg.py plot/verify, drg.py
# parents) and re-samples them at the requested fractions; a power-of-two subset is really plotted +
# reconstructed + checked with verify_v3, and one real recompute is timed. See results/C1_NOTES.md.
#
# New code in a new file (CLAUDE.md §2): imports/reads only — rpos/rpos.py and all of phase1/* and
# node/* stay byte-identical.
#
# Frozen C1 workload: measured N {2^18,2^20,2^22}, DRG in-degree headline 2 / secondary {2,4,8},
# label fractions {1,5,10,25,50,75,100}%, response-timeout grid {1,2,5}s, seed 20260919,
# native rate 20.36 MH/s (phase1/results/chainrate.csv).
#
# Usage:
#   bash experiments/run_c1.sh                                  # full sweep -> CSV + PNG + NOTES numbers
#   C1_QUICK=1 bash experiments/run_c1.sh                       # drop N=2^22 (fast iteration)
#   C1_FRACTIONS="1,10,50,100" C1_DELTAS="2" bash experiments/run_c1.sh   # smoke subset
#   C1_NO_VALIDATE=1 bash experiments/run_c1.sh                 # skip the real verify_v3 anchors
#
# Requires: python3 with numpy + matplotlib (same env as the other experiments). NO Docker.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

# knobs (env-overridable for smoke runs) — forwarded to c1_retention.py
FRACTIONS="${C1_FRACTIONS:-1,5,10,25,50,75,100}"
DELTAS="${C1_DELTAS:-2,4,8}"

args=( --fractions "$FRACTIONS" --deltas "$DELTAS" )
[ "${C1_QUICK:-0}" = "1" ]       && args+=( --quick )
[ "${C1_NO_VALIDATE:-0}" = "1" ] && args+=( --no-validate )
[ "${C1_NO_PLOT:-0}" = "1" ]     && args+=( --no-plot )
[ -n "${C1_SIZES:-}" ]           && args+=( --sizes "$C1_SIZES" )

echo "== [C1] retention attack on the frozen v3 DRG (no Docker) =="
echo "== [C1] fractions=$FRACTIONS deltas=$DELTAS quick=${C1_QUICK:-0} =="
cd "$REPO_ROOT"
exec python3 "$HERE/c1_retention.py" "${args[@]}"
