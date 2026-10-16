#!/usr/bin/env bash
# Issue #46 [B5] — Sybil vs PoSpace admission (Phase 7, examiner point (ii)).
#
# B5 answers: for a fixed STORAGE BUDGET, how many v3-DRG PoSpace identities can an adversary
# create, and what fraction of the chunk space does that buy -- and does PoSpace RAISE the Sybil
# cost? The spine: one admitted identity costs exactly one plot = 32 * N_plot bytes of labels
# (phase1/pospace_drg.py::plot_v3). At the thesis plot REAL_PLOT_N = 3,355,443,200 leaves that is
# 100 GiB of labels, so #identities = floor(budget / 100 GiB). WITHOUT admission an identity is just
# a keypair (~33 B) -> ~unbounded identities -> full chunk control; WITH v3-DRG PoSpace each identity
# is pinned to a real ~100 GiB plot, and a plot cannot be amortised across identities (k ids need k
# distinct pks -> k distinct plots). PoSpace raises the per-identity cost ~ (32*N_plot)/|pk| ~= 3.25e9x.
#
# UNLIKE A1-A6 AND LIKE A7/B2, THIS IS A MICROBENCHMARK, NOT A DOCKER TESTBED RUN (and needs no
# Docker): "identities per GB" and "chunk control" are pure, verifier-reproducible computations over
# the frozen parameters. B5 reuses the exact host-side converged-ring + replica toolkit from
# experiments/b1_placement.py (the model the node, the sims, B1, B2 and B4 share) and node/ids.py,
# and additionally proves the NO-AMORTISATION property on a REAL in-process PoSpace ring
# (source=admission_inproc, the A7 pattern): k distinct Sybils each build their own v3 plot (k
# distinct commitment roots) and the pk<->id binding blocks plot reuse. See results/B5_NOTES.md.
#
# New code in a new file (CLAUDE.md §2): imports/reads only — rpos/rpos.py, node/chord.py,
# node/storage.py, node/ledger.py, node/pospace_admission.py, node/net.py, phase1/pospace_drg.py,
# phase1/drg.py and experiments/b1_placement.py stay byte-identical.
#
# Frozen B5 workload (PARAMETERS.md): thesis plot REAL_PLOT_N (100 GiB/identity), s=3, budget sweep
# {100 GiB .. 100 PiB}, honest ring sizes {32, 1e3, 1e6}, measured N=32 structural anchor, seed
# 20260919, in-process demo at test plot 2^10.
#
# Usage:
#   bash experiments/run_b5.sh                              # self-test, then full analysis -> CSV+PNG
#   B5_NO_DEMO=1 bash experiments/run_b5.sh                 # skip the in-process admission demo
#   B5_BUDGETS="100GiB,1TiB" bash experiments/run_b5.sh     # quick budget subset
#   B5_SKIP_SELFTEST=1 bash experiments/run_b5.sh           # analysis only
#
# Requires: python3 (the 3.11 experiment env) with matplotlib; the in-process demo also needs
# dnspython (it is skipped with a clear note if absent — the cost blocks run anywhere). NO Docker.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

BUDGETS="${B5_BUDGETS:-100GiB,1TiB,10TiB,100TiB,1PiB,10PiB,100PiB}"
SEED="${B5_SEED:-20260919}"

args=( --budgets "$BUDGETS" --seed "$SEED" )
[ "${B5_NO_DEMO:-0}" = "1" ] && args+=( --no-demo )
[ "${B5_NO_PLOT:-0}" = "1" ] && args+=( --no-plot )

cd "$REPO_ROOT"

if [ "${B5_SKIP_SELFTEST:-0}" != "1" ]; then
    echo "== [B5] self-test (deterministic, no Docker) =="
    python3 "$HERE/b5_sybil.py" --self-test
fi

echo "== [B5] Sybil / chunk-control analysis (no Docker) — budgets=$BUDGETS seed=$SEED =="
exec python3 "$HERE/b5_sybil.py" "${args[@]}"
