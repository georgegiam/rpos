#!/usr/bin/env bash
# Issue #54 [C5] — Full Chia-vs-proposed PoSpace comparison table + "what is lost" discussion
# (Phase 8 CAPSTONE, examiner point (i)).
#
# C5 is the row-by-row security comparison the examiner asked for: Chia PoSpace vs the proposed v3
# DRG scheme, with the explicit "what is lost by gaining efficiency" column, plus a 1-2 page synthesis
# discussion. It answers "what security does the proposed scheme trade away for its lower cost, and is
# that trade-off justified for DNS resolution?"
#
# PURE SYNTHESIS, NOT A MEASUREMENT (and needs no Docker): every PROPOSED-side number is pulled from an
# already-committed repo measurement (C1-C4, B2, B5, Phase 1); every CHIA-side number is cited to a
# published source (URL in the CSV `chia_source` column). The driver's --self-test re-reads the source
# CSVs and asserts every numeric table cell still equals its source cell (CLAUDE.md §2 "measure, don't
# assert"), so the capstone table cannot silently drift from the experiments it summarises.
#
# FAIRNESS (the issue's explicit requirement): the table includes every row in BOTH directions — rows
# where Chia wins and rows where the proposed scheme wins. No cherry-picking.
#
# New code in new files (CLAUDE.md §2): rpos/rpos.py, all of phase1/* and node/* stay byte-identical;
# this driver only RE-READS committed results/ CSVs.
#
# Deliverables: results/C5_comparison_table.csv (generated here) + results/C5_comparison_table.md
# (the table + discussion, authored to match the CSV). No figure (the issue does not ask for one).
#
# Usage:
#   bash experiments/run_c5.sh                 # self-test, then emit the CSV
#   C5_SKIP_SELFTEST=1 bash experiments/run_c5.sh   # emit only (not recommended)
#   python3 experiments/c5_comparison.py --self-test  # validate cells against sources only
#
# Requires: python3 (stdlib only — csv/argparse). NO Docker, NO numpy/matplotlib.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
cd "$REPO_ROOT"

if [ "${C5_SKIP_SELFTEST:-0}" != "1" ]; then
  echo "== [C5] self-test: validate every table cell against its committed source CSV =="
  python3 "$HERE/c5_comparison.py" --self-test
fi

echo "== [C5] emit comparison table -> results/C5_comparison_table.csv =="
exec python3 "$HERE/c5_comparison.py"
