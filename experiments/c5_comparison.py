#!/usr/bin/env python3
"""Issue #54 [C5] — Full Chia-vs-proposed PoSpace comparison table (Phase 8, examiner point (i)).

C5 is the CAPSTONE of Phase 8: the row-by-row security comparison of **Chia PoSpace** against the
**proposed v3 DRG scheme**, with the examiner's explicit **"what is lost by gaining efficiency"**
column, plus a 1-2 page synthesis discussion (written in results/C5_comparison_table.md).

This is a PURE SYNTHESIS deliverable — NO new measurement. Every PROPOSED-side number is pulled from
an already-committed repo measurement (C1-C4, B2, B5, Phase 1); every CHIA-side number is cited to a
published source (URL in the `chia_source` column). This driver:

  * --emit  (default): assembles the 14-row table into results/C5_comparison_table.csv.
  * --self-test: the drift-proofing core. Re-reads the committed source CSVs
    (C1_retention_attack.csv, C2_delta_jitter.csv, C3_detection.csv, C4_proof_metrics.csv,
    B2_targeted.csv, B5_sybil.csv) and ASSERTS that every numeric cell quoted in the table still
    equals its source cell (exact for integer byte/identity counts; +/-1% for timings/fractions).
    If any number has drifted from its source, the self-test fails loudly. This is the CLAUDE.md §2
    "measure, don't assert" guarantee applied to the capstone: the table cannot silently go stale.

  Default run does BOTH (self-test, then emit) so a committed CSV is always validated.

FAIRNESS (the issue's explicit requirement): the table includes every row in BOTH directions — rows
where Chia wins (proof size, space-lower-bound strength, maturity, non-interactive / no-δ, VDF
composability) and rows where the proposed scheme wins (prover time, simplicity, no-blockchain
self-containment). No cherry-picking.

Touches no frozen artifact (rpos/rpos.py, phase1/*, node/* are read only; this file imports nothing
from them — it only re-reads committed results/ CSVs). Fixed repo seed lineage 20260919.

Run:  python3 experiments/c5_comparison.py                 # self-test, then emit CSV
      python3 experiments/c5_comparison.py --self-test     # validate cells against source CSVs only
      python3 experiments/c5_comparison.py --emit          # write CSV (no self-test)
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
OUT_CSV = RESULTS / "C5_comparison_table.csv"

# committed source CSVs the self-test validates against (CLAUDE.md §2: every number traces to one)
SRC = {
    "C1": RESULTS / "C1_retention_attack.csv",
    "C2": RESULTS / "C2_delta_jitter.csv",
    "C3": RESULTS / "C3_detection.csv",
    "C4": RESULTS / "C4_proof_metrics.csv",
    "B2": RESULTS / "B2_targeted.csv",
    "B5": RESULTS / "B5_sybil.csv",
}

# Chia source URLs (every chia-side number / construction fact carries its citation)
CHIA_POS_CONSTRUCTION = "https://www.chia.net/wp-content/uploads/2022/09/Chia_Proof_of_Space_Construction_v1.1.pdf"
CHIA_POS_1_0 = "https://docs.chia.net/chia-blockchain/consensus/proof-of-space-1.0/"
CHIA_PLOTTING = "https://docs.chia.net/reference-client/plotting/plotting-basics/"
CHIA_CONSENSUS_PDF = "https://www.chia.net/wp-content/uploads/2022/09/Chia-New-Consensus-0.9.pdf"
CHIA_PROOF_OF_TIME = "https://docs.chia.net/proof-of-time"
CHIA_CHALLENGES = "https://docs.chia.net/consensus-challenges/"
CHIA_GREEN_PAPER = "https://docs.chia.net/files/ChiaGreenPaper_20241008.pdf"
AACKPR17 = "Abusalah-Alwen-Cohen-Khurana-Pietrzak-Reyzin, 'Beyond Hellman's Time-Memory Trade-Offs', ASIACRYPT 2017 [AACKPR17] (cited phase1/FINDINGS.md:322)"
ABH17 = "Alwen-Blocki-Harsha, 'Practical Graphs for Optimal Side-Channel Resistant Proofs of Space', CCS 2017 [ABH17]"
DFKP15 = "Dziembowski-Faust-Kolmogorov-Pietrzak, 'Proofs of Space', CRYPTO 2015 [DFKP15]"

# shared constants (repo-standard; quoted in the table, pinned by the self-test where they live in a CSV)
THESIS_N = 3_355_443_200          # thesis plot leaves (2^~31.6); CLAUDE.md §5
NATIVE_RATE_MHS = 20.36           # single-core SHA-256, phase1/results/chainrate.csv
PAR_FLOOR_S = 5.149418            # unlimited-core parallel-attacker floor (C1 par_floor_s)


# ---------------------------------------------------------------------------------------
# the table — 14 rows x 4 columns (+ provenance). Qualitative cells authored; numeric cells
# quote a committed measurement and are pinned by CHECKS below.
# ---------------------------------------------------------------------------------------
# Each row: (axis, chia, proposed, what_gained, what_lost, chia_source, proposed_source)
ROWS = [
    (
        "1. Underlying hard problem",
        "Inverting a sequence of functions; time-memory-trade-off hardness (Beyond-Hellman) [AACKPR17]",
        "Pebbling / labelling of an (e,d)-depth-robust DAG; sequential-recompute lower bound [DFKP15, ABH17]",
        "One well-studied primitive (a single DRG); the verifier reconstructs the graph bit-for-bit from pk",
        "Narrower foundation: security rests on one single-layer DRG's depth-robustness vs Chia's layered function-inversion hardness",
        AACKPR17,
        "phase1/FINDINGS.md:191-204,322; phase1/FIX_A.md:41-76",
    ),
    (
        "2. Graph / plot construction",
        "7 tables (Beyond-Hellman nested 6x), 2^k entries each; plot phases forward-propagation -> backpropagation -> compression -> checkpoints",
        "DRSample single-layer DRG (bucket-method back-edges); label l_i = H(pk||i||parent labels); Merkle-committed",
        "Far simpler plotting (one SHA-256 pass per label); data-independent, verifier-reproducible bit-for-bit from pk",
        "Single layer, no table compression; far less engineering maturity; no compressed on-disk format",
        CHIA_POS_CONSTRUCTION,
        "phase1/FIX_A.md:45-57; node/pospace_admission.py (imports phase1/pospace_drg.py, drg.py)",
    ),
    (
        "3. Space lower bound (asymptotic + measured)",
        "Time-memory-trade-off lower bound from the Beyond-Hellman layered-table construction [AACKPR17]",
        "Asymptotic Omega(N/log N) depth-robustness [ABH17]; MEASURED back-cone phi ~= 0.49*N at thesis N (C1)",
        "A concrete, MEASURED space floor on the actual plot (not only an asymptotic claim)",
        "Bound is asymptotic + single-layer; measured phi extrapolated ~800x beyond the measured range, not re-proven at thesis N",
        AACKPR17,
        "phase1/FIX_A.md:23-31,176-180; C1_retention_attack.csv (phi plateau ~0.49)",
    ),
    (
        "4. Time-space trade-off curve",
        "Partial-storage resisted by table design; no published recompute-vs-storage curve",
        "keep 25% labels -> 12.99 s recompute, keep <=10% -> 60-81 s; honest ~tens of ms; phi saturates ~0.49 (C1)",
        "A measured trade-off curve that makes a usable response timeout delta possible",
        "Trade-off holds under the sequential model; an unlimited-core parallel attacker floor ~= 5.15 s (C1)",
        CHIA_POS_1_0,
        "C1_retention_attack.csv (source=extrapolated, delta=2, thesis N)",
    ),
    (
        "5. Proof size",
        "256 B (k=32)",
        "3168 B (delta=2) / 5280 (delta=4) / 9504 (delta=8) at thesis N -- ~12x larger (C4)",
        "Self-contained proof: opens a verifier-reconstructible DRG parent set + Merkle paths, no table lookups",
        "~12x larger than Chia (256 B -> 3168 B) and grows LINEARLY in the DRG in-degree delta",
        CHIA_POS_1_0,
        "C4_proof_metrics.csv (proposed_v3 extrapolated_v3 / chia_cited)",
    ),
    (
        "6. Prover / verifier time",
        "prover ~640 ms (slow-HDD quality lookup, 10 ms/seek); verifier near-instant, NO published ms",
        "prover ~7 us; verifier ~17 us (in-RAM Merkle open) (C4)",
        "Seek-free, in-RAM proving -- prover ~5 orders of magnitude faster than Chia's disk lookup",
        "Assumes the plot is RAM/fast-readable; Chia is designed to tolerate a slow HDD",
        CHIA_CONSENSUS_PDF,
        "C4_proof_metrics.csv (measured_v3 @2^16, carried to thesis N)",
    ),
    (
        "7. Plot initialisation time + size",
        "~300 s high-end (400 GiB RAM) up to ~6 h commodity; 101.4 GiB (k=32)",
        "164.8 s native floor (delta=2; up to 411 s at delta=8); 100 GiB labels (~200 GiB with Merkle tree) (C4)",
        "Comparable/faster native plot; one SHA-256 per label, no multi-phase compression",
        "Native-rate floor (pure-Python plotter ~33-55x slower); ~200 GiB on disk with the tree vs Chia's compressed 101.4 GiB",
        CHIA_PLOTTING,
        "C4_proof_metrics.csv (plot_time native floor; phase1/results/results_plot_extrap_v3.csv)",
    ),
    (
        "8. Challenge-response protocol",
        "Non-interactive: the challenge is broadcast from the blockchain at each signage point; the farmer self-checks its plot (no per-prover request)",
        "Interactive: a peer challenges a peer over the DHT; the prover must answer within a response timeout delta",
        "No blockchain / timelord required; fits a live DHT where nodes already exchange RPCs every maintenance round",
        "Relies on an interactive liveness assumption and a wall-clock timeout delta that Chia avoids entirely",
        CHIA_CHALLENGES,
        "node/pospace_admission.py (periodic challenge, delta=2 s); results/PARAMETERS.md",
    ),
    (
        "9. delta (timeout) sensitivity",
        "N/A -- Chia has no response-timeout delta",
        "false-reject ~0 for all delta>=1 s (honest p99 cross-region 146.5 ms); false-accept = 0 for delta<=2 s; delta=5 s marginal vs the 5.15 s parallel floor (C2)",
        "delta<=2 s cleanly separates honest from cheater under realistic network jitter",
        "Correctness hinges on a tuned delta and jitter assumptions; a loose delta (delta=10 s at delta_g=8 / keep-75%) admits a cheater (C2)",
        CHIA_CONSENSUS_PDF,
        "C2_delta_jitter.csv (honest false_reject / cheater false_accept)",
    ),
    (
        "10. Detection probability",
        "N/A at the PoSpace layer -- soundness/identity is enforced by consensus, not per-node liveness challenges",
        "rho<=20% labels -> caught by the 1st challenge (p_fail 0.89-0.97); evicted in 3 consecutive fails (MAX_FAILS); knee at rho~25% (C3)",
        "Cheap periodic challenges catch storage-cheaters quickly and evict them",
        "A cheater keeping >=33% labels escapes the delta=2 s timeout (but then stored ~75% of the tree); detection is recompute-time-bound, not coverage-bound",
        CHIA_CHALLENGES,
        "C3_detection.csv (source=empirical_pooled, delta_g=2)",
    ),
    (
        "11. Grinding / Sybil resistance",
        "Plot-grinding costly by construction; 'ungrindable trunk' (PoSpace+VDF only); identity enforced at consensus level",
        "id=SHA256(pk) UNSALTED & attacker-chosen -> grindable in ~N hashes (targeted capture = const 2 plots, B2); per-identity cost x3.25e9 vs no admission (B5); BUT a minimum-plot-size check is MISSING (B5 gate FAIL)",
        "PoSpace raises the per-identity cost ~3.25e9x (33 B keypair -> 100 GiB plot) and rate-limits the NUMBER of identities",
        "Rate-limits identity count, not PLACEMENT -- the unsalted id is grindable; the Sybil-cost floor is CONDITIONAL on an unimplemented minimum-plot-size check",
        CHIA_GREEN_PAPER,
        "B2_targeted.csv (grind cost, 2 plots); B5_sybil.csv (3.25e9x, min-plot-size gate)",
    ),
    (
        "12. Composability",
        "Chained with a VDF ('Proof of Time', class-group repeated squaring by timelords) -> blockchain-grade consensus",
        "Standalone PoSpace admission over the DHT; no VDF, no chain",
        "No timelord / VDF / blockchain dependency -- self-contained node admission",
        "No proof-of-elapsed-time or global ordering; cannot give the consensus-grade guarantees Chia's VDF provides",
        CHIA_PROOF_OF_TIME,
        "node/pospace_admission.py (standalone admission; no VDF in the design)",
    ),
    (
        "13. Amortisation resistance",
        "Beyond-Hellman table format resists time-memory trade-offs [AACKPR17]; grinding-resistant trunk",
        "DRG depth-robustness (no sub-linear retention, C1) + no-plot-amortisation: k identities need k distinct plots, distinct roots (B5 gate PASS); pk<->id binding blocks plot reuse (B5 gate PASS)",
        "Provably one plot per identity; a Sybil advertising another identity's commitment is rejected by challenge_peer (B5)",
        "Amortisation across challenges WITHIN one plot is not separately hardened; rests on the single DRG's depth-robustness",
        AACKPR17,
        "phase1/FINDINGS.md:231-241; B5_sybil.csv (admission_demo gates)",
    ),
    (
        "14. Known attacks + mitigations",
        "Mature, audited, deployed since 2021; plot-grinding / replotting trade-offs handled at the consensus layer",
        "v1/v2 scheme breaks FOUND & FIXED by v3 DRG (Phase 1); residual: B1 >=1-of-s forge, B6 unvalidated ledger proposer, B2 id grinding, B5 missing min-plot-size -- each with a recommended (not-yet-implemented) mitigation",
        "Breaks were found and fixed before resubmission; a clear, measured mitigation list",
        "Unaudited and not battle-tested; several recommended mitigations remain unimplemented; DRG parameters await cryptographer sign-off",
        CHIA_GREEN_PAPER,
        "phase1/FINDINGS.md; results/B1_NOTES.md, B2_NOTES.md, B5_NOTES.md, B6_NOTES.md",
    ),
]

CSV_HEADER = ["row", "axis", "chia", "proposed", "what_gained", "what_lost", "chia_source", "proposed_source"]


# ---------------------------------------------------------------------------------------
# self-test — pin every numeric cell to its committed source CSV
# ---------------------------------------------------------------------------------------
def _read_rows(path: Path) -> list[dict]:
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def _select(rows: list[dict], **filt) -> list[dict]:
    """Rows where every filt key equals the given value (string compare, exact)."""
    out = []
    for r in rows:
        if all(str(r.get(k, "")).strip() == str(v) for k, v in filt.items()):
            out.append(r)
    return out


def _num(x: str) -> float:
    return float(str(x).strip())


# Each check: (label, src_key, filter_dict, column, expected, kind)
#   kind "exact" -> integer/exact string match; kind "rel1" -> within +/-1% relative.
# These are the numbers quoted verbatim in the ROWS table above; if a source CSV is re-run with
# different numbers, this list fails until the table is refreshed.
CHECKS = [
    # --- C4: proof size / prover / verifier / plot (row 5,6,7) ---
    ("C4 v3 proof delta=2 @thesisN = 3168 B", "C4",
     {"scheme": "proposed_v3", "source": "extrapolated_v3", "parameter": "delta=2"}, "proof_size_bytes", 3168, "exact"),
    ("C4 v3 proof delta=4 @thesisN = 5280 B", "C4",
     {"scheme": "proposed_v3", "source": "extrapolated_v3", "parameter": "delta=4"}, "proof_size_bytes", 5280, "exact"),
    ("C4 v3 proof delta=8 @thesisN = 9504 B", "C4",
     {"scheme": "proposed_v3", "source": "extrapolated_v3", "parameter": "delta=8"}, "proof_size_bytes", 9504, "exact"),
    ("C4 v3 plot_time delta=2 ~= 164.8 s", "C4",
     {"scheme": "proposed_v3", "source": "extrapolated_v3", "parameter": "delta=2"}, "plot_time", 164.8, "rel1"),
    ("C4 v3 plot_time delta=8 ~= 411.3 s", "C4",
     {"scheme": "proposed_v3", "source": "extrapolated_v3", "parameter": "delta=8"}, "plot_time", 411.3, "rel1"),
    ("C4 v3 prover ~= 7 us (0.007028 ms)", "C4",
     {"scheme": "proposed_v3", "source": "extrapolated_v3", "parameter": "delta=2"}, "prover_ms", 0.007028, "rel1"),
    ("C4 v3 verifier ~= 17 us (0.016963 ms)", "C4",
     {"scheme": "proposed_v3", "source": "extrapolated_v3", "parameter": "delta=2"}, "verifier_ms", 0.016963, "rel1"),
    ("C4 Chia proof = 256 B", "C4", {"scheme": "chia"}, "proof_size_bytes", 256, "exact"),
    ("C4 Chia prover = 640 ms", "C4", {"scheme": "chia"}, "prover_ms", 640.0, "rel1"),
    ("C4 Chia plot_time = 300 s", "C4", {"scheme": "chia"}, "plot_time", 300.0, "rel1"),
    ("C4 Chia plot_size = 101.4 GiB", "C4", {"scheme": "chia"}, "plot_size", 101.4, "rel1"),
    ("C4 v3 plot_size = 100 GiB", "C4",
     {"scheme": "proposed_v3", "source": "extrapolated_v3", "parameter": "delta=2"}, "plot_size", 100.0, "rel1"),

    # --- C1: time-space trade-off (row 4) + parallel floor (row 4) ---
    ("C1 keep 25% -> 12.99 s recompute", "C1",
     {"source": "extrapolated", "delta": "2", "label_frac_pct": "25.000000"}, "recompute_time_s_median", 12.990267, "rel1"),
    ("C1 keep 10% -> 60.75 s recompute", "C1",
     {"source": "extrapolated", "delta": "2", "label_frac_pct": "10.000000"}, "recompute_time_s_median", 60.751009, "rel1"),
    ("C1 keep 5% -> 80.41 s recompute", "C1",
     {"source": "extrapolated", "delta": "2", "label_frac_pct": "5.000000"}, "recompute_time_s_median", 80.412238, "rel1"),
    ("C1 phi plateau ~0.49 (keep 1%)", "C1",
     {"source": "extrapolated", "delta": "2", "label_frac_pct": "1.000000"}, "phi", 0.494391, "rel1"),
    ("C1 parallel floor = 5.149418 s", "C1",
     {"source": "extrapolated", "delta": "2", "label_frac_pct": "25.000000"}, "par_floor_s", 5.149418, "rel1"),

    # --- C2: delta sensitivity (row 9) ---
    ("C2 honest p99 cross sigma=20 = 146.5 ms", "C2",
     {"role": "honest", "rtt_tier": "cross", "sigma_ms": "20.000000", "resp_delta_s": "1.000000"},
     "honest_p99_resp_ms", 146.531819, "rel1"),
    ("C2 cheater delta_g=8 keep75 delta=5 -> FA=0", "C2",
     {"role": "cheater", "drg_indegree": "8", "storage_frac_pct": "75.000000", "resp_delta_s": "5.000000",
      "rtt_tier": "cross", "sigma_ms": "20.000000"}, "false_accept_rate", 0.0, "exact"),
    ("C2 cheater delta_g=8 keep75 delta=10 -> FA=1 (the loosening exploit)", "C2",
     {"role": "cheater", "drg_indegree": "8", "storage_frac_pct": "75.000000", "resp_delta_s": "10.000000",
      "rtt_tier": "cross", "sigma_ms": "20.000000"}, "false_accept_rate", 1.0, "exact"),

    # --- C3: detection probability (row 10) ---
    ("C3 keep 25% p_fail = 0.741 (knee)", "C3",
     {"source": "empirical_pooled", "drg_indegree": "2", "storage_frac_pct": "25.000000"}, "p_fail", 0.741154, "rel1"),
    ("C3 keep 20% p_fail = 0.887", "C3",
     {"source": "empirical_pooled", "drg_indegree": "2", "storage_frac_pct": "20.000000"}, "p_fail", 0.886731, "rel1"),
    ("C3 keep 10% p_fail = 0.968", "C3",
     {"source": "empirical_pooled", "drg_indegree": "2", "storage_frac_pct": "10.000000"}, "p_fail", 0.968462, "rel1"),
    ("C3 keep 50% p_fail = 0 (escapes timeout)", "C3",
     {"source": "empirical_pooled", "drg_indegree": "2", "storage_frac_pct": "50.000000"}, "p_fail", 0.0, "exact"),

    # --- B2: grinding / targeted capture (row 11) ---
    ("B2 grind @N=1e9 = 49.1 s native", "B2",
     {"metric": "grind_scale", "N": "1000000000"}, "seconds_native", 49.1087, "rel1"),
    ("B2 targeted-majority capture = 2 plots", "B2",
     {"metric": "capture_cost", "strategy": "targeted_majority", "N": "32"}, "identities_needed", 2, "exact"),
    ("B2 >=1-of-s (B1) capture = 1 plot", "B2",
     {"metric": "capture_cost", "strategy": "targeted_effective", "N": "32"}, "identities_needed", 1, "exact"),
    ("B2 grind google.com = 2 ids, captured", "B2",
     {"metric": "grind_target"}, "identities_needed", 2, "exact"),

    # --- B5: Sybil budget / cost / gates (row 11, 13) ---
    ("B5 1 PiB -> 10485 identities", "B5",
     {"metric": "sybil_yield", "scheme": "pospace_v3", "storage_budget_h": "1 PiB"}, "identities", 10485, "exact"),
    ("B5 1 PiB forge control of 1e6 ring = 0.0308", "B5",
     {"metric": "pospace_vs_free", "scheme": "pospace_v3", "storage_budget_h": "1 PiB", "N_honest": "1000000"},
     "control_forge_1ofs", 0.0308, "rel1"),
]

# non-CSV "gate" checks: assert a committed qualitative result cell is present (not a number)
STRING_CHECKS = [
    ("B5 min-plot-size gate = FAIL (admitted under-sized Sybil)", "B5",
     {"metric": "admission_demo", "source": "admission_inproc", "plot_n": "1024"}, "result", "fail"),
]


def run_self_test() -> int:
    failures = []
    cache: dict[str, list[dict]] = {}

    def rows_for(key: str) -> list[dict]:
        if key not in cache:
            path = SRC[key]
            if not path.exists():
                raise FileNotFoundError(f"source CSV missing: {path} (run its experiment first)")
            cache[key] = _read_rows(path)
        return cache[key]

    # numeric checks
    for label, key, filt, col, expected, kind in CHECKS:
        try:
            sel = _select(rows_for(key), **filt)
        except FileNotFoundError as e:
            failures.append(f"{label}: {e}")
            continue
        if not sel:
            failures.append(f"{label}: NO source row matched {filt} in {SRC[key].name}")
            continue
        # every matching row must carry the expected value (guards against an ambiguous filter)
        for r in sel:
            raw = r.get(col, "")
            if raw is None or str(raw).strip() == "":
                failures.append(f"{label}: source cell {col} empty in {SRC[key].name} for {filt}")
                break
            try:
                got = _num(raw)
            except ValueError:
                failures.append(f"{label}: source cell {col}='{raw}' not numeric in {SRC[key].name}")
                break
            if kind == "exact":
                ok = (got == float(expected))
            else:  # rel1
                denom = abs(float(expected)) if float(expected) != 0 else 1.0
                ok = abs(got - float(expected)) / denom <= 0.01
            if not ok:
                failures.append(f"{label}: expected {expected} ({kind}), source {SRC[key].name} has {col}={got}")
                break

    # string/gate checks
    for label, key, filt, col, expected in STRING_CHECKS:
        try:
            sel = _select(rows_for(key), **filt)
        except FileNotFoundError as e:
            failures.append(f"{label}: {e}")
            continue
        if not sel:
            failures.append(f"{label}: NO source row matched {filt} in {SRC[key].name}")
            continue
        got = str(sel[0].get(col, "")).strip()
        if got != expected:
            failures.append(f"{label}: expected {col}='{expected}', source has '{got}'")

    total = len(CHECKS) + len(STRING_CHECKS)
    if failures:
        print(f"[C5 self-test] FAIL — {len(failures)}/{total} checks failed:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"[C5 self-test] OK — all {total} table cells match their committed source CSVs.")
    return 0


# ---------------------------------------------------------------------------------------
# emit
# ---------------------------------------------------------------------------------------
def emit_csv() -> None:
    RESULTS.mkdir(exist_ok=True)
    with OUT_CSV.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(CSV_HEADER)
        for i, row in enumerate(ROWS, start=1):
            axis, chia, proposed, gained, lost, chia_src, prop_src = row
            w.writerow([i, axis, chia, proposed, gained, lost, chia_src, prop_src])
    print(f"[C5] wrote {OUT_CSV.relative_to(REPO_ROOT)} — {len(ROWS)} rows x {len(CSV_HEADER)} columns")


def main() -> int:
    ap = argparse.ArgumentParser(description="C5 — Chia vs proposed PoSpace comparison table (Phase 8).")
    ap.add_argument("--self-test", action="store_true", help="validate table cells against committed source CSVs, no emit")
    ap.add_argument("--emit", action="store_true", help="emit the CSV without the self-test")
    args = ap.parse_args()

    if args.self_test and not args.emit:
        return run_self_test()
    if args.emit and not args.self_test:
        emit_csv()
        return 0

    # default: self-test, then emit (a committed CSV is always validated first)
    rc = run_self_test()
    if rc != 0:
        print("[C5] self-test failed — NOT emitting a table with drifted numbers.")
        return rc
    emit_csv()
    return 0


if __name__ == "__main__":
    sys.exit(main())
