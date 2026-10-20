#!/usr/bin/env bash
# Issue #53 [C4] — Proof size & prover/verifier time, measured against Chia
# (Phase 8, examiner point (i)).
#
# C4 collects the CONCRETE COSTS of each Proof-of-Space scheme for the fair side-by-side the
# examiner asked for: proof size, prover time, verifier time, plot time, plot size — MEASURED for
# the PROPOSED v3 DRG scheme, CITED for Chia. It feeds the C5 comparison table ("what is lost by
# gaining efficiency"). No estimates: every v3 number traces to a repo measurement, every Chia
# number to a published source, and every scale/hardware mismatch is flagged (CLAUDE.md §2).
#
# LIKE A7/B2/B5/C1-C3 THIS IS A MICROBENCHMARK, NOT A DOCKER TESTBED RUN (and needs no Docker):
# proof/prover/verifier/plot costs are properties of the PoSpace plot, not the DNS ring. The driver
# REUSES THE A7 HARNESS for a fresh v3 anchor (times the node-imported plot_v3/commit_v3/prove_v3/
# verify_v3), reads the committed thesis-scale native plot time (results/results_plot_extrap_v3.csv)
# and the exact proof-size formula, and pairs them with cited Chia k=32 numbers. See C4_NOTES.md.
#
# New code in a new file (CLAUDE.md §2): imports/reads only — rpos/rpos.py, all of phase1/* and
# node/* stay byte-identical.
#
# Deliverables: results/C4_proof_metrics.csv + results/fig_C4_proof_metrics.png (+ C4_NOTES.md).
#
# Usage:
#   bash experiments/run_c4.sh                                 # self-test, then full run -> CSV + PNG
#   C4_ANCHOR_LOG2=14 C4_REPEATS=2 bash experiments/run_c4.sh  # faster anchor (smoke)
#   C4_NO_PLOT=1 bash experiments/run_c4.sh                    # table only
#   C4_SKIP_SELFTEST=1 bash experiments/run_c4.sh              # skip the pre-run self-test
#
# Requires: python3 with numpy + matplotlib (same env as the other experiments). NO Docker.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

# knobs (env-overridable for smoke runs) — forwarded to c4_proof_metrics.py
ANCHOR_LOG2="${C4_ANCHOR_LOG2:-16}"
REPEATS="${C4_REPEATS:-3}"
DELTAS="${C4_DELTAS:-2,4,8}"

args=( --anchor-log2 "$ANCHOR_LOG2" --repeats "$REPEATS" --deltas "$DELTAS" )
[ "${C4_NO_PLOT:-0}" = "1" ] && args+=( --no-plot )

cd "$REPO_ROOT"

if [ "${C4_SKIP_SELFTEST:-0}" != "1" ]; then
  echo "== [C4] self-test (deterministic, no Docker) =="
  python3 "$HERE/c4_proof_metrics.py" --self-test
fi

echo "== [C4] proof size & prover/verifier time vs Chia (no Docker) =="
echo "== [C4] anchor=2^$ANCHOR_LOG2 repeats=$REPEATS deltas=$DELTAS =="
exec python3 "$HERE/c4_proof_metrics.py" "${args[@]}"
