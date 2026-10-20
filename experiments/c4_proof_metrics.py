#!/usr/bin/env python3
"""Issue #53 [C4] — Proof size & prover/verifier time, measured against Chia
(Phase 8, examiner point (i)).

C4 collects the CONCRETE COSTS of each Proof-of-Space scheme for the fair side-by-side the
examiner asked for: proof size (bytes), prover time, verifier time, plot time, plot size — MEASURED
for the PROPOSED v3 DRG scheme, CITED for Chia. It answers "what are the concrete costs of each
scheme?" and feeds the C5 comparison table (incl. the "what is lost by gaining efficiency"
discussion). No estimates: every v3 number traces to a repo measurement, every Chia number to a
published source, and every scale/hardware mismatch is flagged (CLAUDE.md §2).

The PROPOSED-scheme costs are already measured and committed in frozen artifacts; C4 reuses the
A7 harness for a FRESH anchor and assembles the rest (imports/reads only, no frozen edit):
  * source=measured_v3  — a fresh measurement at a representative test size (default 2^16) over
    δ∈{2,4,8}, timing the node-imported plot_v3/commit_v3/prove_v3/verify_v3 exactly as
    experiments/a7_admission.py does (same perf_counter timing, same proof-byte recipe
    sum(len(lbl)+32*len(path))). Cross-cites results/A7_admission.csv (the committed A7 sweep).
  * source=extrapolated_v3 — the FAIR same-scale row at the thesis plot N = REAL_PLOT_N
    (≈100 GiB labels ≈ Chia k=32's 101.4 GiB): proof size via the exact measured==analytic formula
    (1+δ)·(1+⌈log₂N⌉)·32 B (phase1/FIX_A.md §4); prover/verifier carried from the measured anchor
    (size-independent to first order — the extra Merkle levels add a handful of hashes, ≪ RTT);
    plot_time = the native-rate floor read from results/results_plot_extrap_v3.csv; plot_size =
    100 GiB labels (≈200 GiB with the Merkle tree).
  * source=chia_cited — Chia k=32, every field with its published source URL in the note column.

Scale/mismatch honesty: our directly-measured anchors are at toy N (2^16); the thesis-scale v3
row is extrapolated (plot time from the committed native-rate model; proof size from the exact
formula; prove/verify size-independent). Chia numbers are at real k=32 scale. Chia's verifier time
is "near-instant / a few hashes" with NO published ms benchmark, and its prover (quality lookup)
is cited at ~640 ms on a slow HDD (10 ms/seek, plot-size-independent) — both flagged, not asserted.

Touches no frozen artifact (rpos/rpos.py, phase1/*, node/* imported/read only). Fixed seed 20260919.

Run:  python3 experiments/c4_proof_metrics.py                 # measure + assemble -> CSV + PNG
      python3 experiments/c4_proof_metrics.py --no-plot       # table only
      python3 experiments/c4_proof_metrics.py --self-test     # deterministic checks, no Docker
      python3 experiments/c4_proof_metrics.py --anchor-log2 14 --repeats 2   # faster anchor
"""
from __future__ import annotations

import argparse
import csv
import math
import random
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
OUT_CSV = RESULTS / "C4_proof_metrics.csv"
OUT_FIG = RESULTS / "fig_C4_proof_metrics.png"
A7_CSV = RESULTS / "A7_admission.csv"
PLOT_EXTRAP_CSV = REPO_ROOT / "phase1" / "results" / "results_plot_extrap_v3.csv"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# import the v3 DRG functions THE SAME WAY THE NODE DOES (and A7 does): node/pospace_admission.py
# re-exports them from phase1/pospace_drg.py and puts phase1/ on sys.path as a side effect.
# Importing runs no _test()/run().
from node.pospace_admission import (  # noqa: E402
    plot_v3, commit_v3, prove_v3, verify_v3,
    PLOT_N as NODE_DEFAULT_PLOT_N, DRG_INDEGREE as NODE_DEFAULT_DELTA,
)
from node.ids import node_id_from_pk    # noqa: E402
from node.run_node import _pk_for       # noqa: E402  (deterministic ring identities)
from drg import parents_all             # noqa: E402  (phase1, on sys.path via the import above)

try:
    from node.pospace_admission import REAL_PLOT_N  # noqa: E402
except Exception:                                   # keep the driver dependency-light
    REAL_PLOT_N = 3_355_443_200

# ---------------------------------------------------------------------------------------
# frozen C4 workload
# ---------------------------------------------------------------------------------------
SEED = 20260919                                   # frozen repo seed (CLAUDE.md §2)
DELTAS = [2, 4, 8]                                # DRG in-degree; 2 = node default = headline
ANCHOR_LOG2 = 16                                  # measured-anchor size 2^16 (A7's largest)
ANCHOR_REPEATS = 3                                # per ring key (A7 used 5; a cross-check anchor)
ANCHOR_CHALLENGES = 30                            # prove/verify calls averaged per (key,repeat)
ANCHOR_RING_N = 8                                 # 8 deterministic ring keys, matching A7
PK_BYTES = 33
LABEL_FIXED = PK_BYTES + 8                        # pk(33) || i(8) before the parent labels
CHAIN_INPUT_BYTES = 32 + PK_BYTES + 8             # the v2 chain hash bench_v3's CHAIN_RATE times


def _sha_blocks(nbytes: int) -> int:              # SHA-256 compression blocks for an nbyte message
    return (nbytes + 9 + 63) // 64
BLOCKS_CHAIN = _sha_blocks(CHAIN_INPUT_BYTES)


def _load_chain_rate(default_hs: float = 20_363_000.0) -> float:
    """hashes/s (native, single core) from phase1/results/chainrate.csv — a7/bench_v3 convention."""
    p = REPO_ROOT / "phase1" / "results" / "chainrate.csv"
    if p.exists():
        for r in csv.reader(open(p)):
            if r and r[0] == "hashes_per_s_median":
                try:
                    return float(r[1])
                except ValueError:
                    pass
            if r and r[0] == "median":                       # fallback: MH/s row
                try:
                    return float(r[1]) * 1e6
                except ValueError:
                    pass
    return default_hs
CHAIN_RATE = _load_chain_rate()


# ---------------------------------------------------------------------------------------
# Chia k=32 — CITED published numbers (sources recorded in the note column + C4_NOTES.md).
# All figures are cited, none measured here. Flags mark what Chia has not published.
# ---------------------------------------------------------------------------------------
CHIA_DOCS_POS1 = "https://docs.chia.net/chia-blockchain/consensus/proof-of-space-1.0/"
CHIA_CONSENSUS_PDF = "https://www.chia.net/wp-content/uploads/2022/09/Chia-New-Consensus-0.9.pdf"
CHIA_PLOTTING = "https://docs.chia.net/reference-client/plotting/plotting-basics/"

CHIA_K32 = {
    "parameter": "k=32",
    # proof = 64 x-values × k bits = 64·32 bits = 256 B (Chia docs, Proof of Space 1.0)
    "proof_size_bytes": 256,
    # quality/proof lookup: ~640 ms on a slow HDD (10 ms/seek), plot-size-INDEPENDENT (consensus PDF)
    "prover_ms": 640.0,
    # verification: "a few hashes + comparisons", no disk → near-instant; NO published ms benchmark
    "verifier_ms": float("nan"),
    # plotting a k=32 plot: ~5 min on high-end (400 GiB RAM) up to ~6 h commodity (Chia 1.2.7 docs)
    "plot_time_s": 300.0,
    # plot size k=32 = 780·k·2^(k−10) bytes ≈ 101.4 GiB (108.8 GB) (Chia docs, Proof of Space 1.0)
    "plot_size_gib": 101.4,
    "note": (f"CITED k=32: proof 256 B (64 x-values × 32 bits) [{CHIA_DOCS_POS1}]; "
             f"plot 101.4 GiB (780·k·2^(k−10)) [{CHIA_DOCS_POS1}]; "
             f"plot time ~5 min high-end (400 GiB RAM) to ~6 h commodity, Chia 1.2.7 [{CHIA_PLOTTING}]; "
             f"prover ~640 ms slow-HDD lookup (10 ms/seek, plot-size-independent) [{CHIA_CONSENSUS_PDF}]; "
             f"verifier near-instant (a few hashes, no disk), NO published ms figure [{CHIA_DOCS_POS1}] (FLAG)"),
}


# ---------------------------------------------------------------------------------------
# proof-size formula — exact and measured==analytic (phase1/FIX_A.md §4; verified in --self-test).
# A proof opens node i + its δ parents (1+δ leaves), each with a Merkle path of log₂N siblings.
# ---------------------------------------------------------------------------------------
def proof_size_formula(N: int, delta: int) -> int:
    """(1+δ)·(1+⌈log₂N⌉)·32 bytes: (1+δ) opened leaves, each 32 B + a ⌈log₂N⌉-sibling Merkle path."""
    plen = math.ceil(math.log2(N))
    return (1 + delta) * (1 + plen) * 32


# ---------------------------------------------------------------------------------------
# source=measured_v3 — fresh anchor, reusing the A7 timing + proof-byte recipe exactly.
# ---------------------------------------------------------------------------------------
def _mean(vals: list[float]) -> float:
    vals = [v for v in vals if not math.isnan(v)]
    return statistics.fmean(vals) if vals else float("nan")


def measure_anchor(N: int, delta: int, repeats: int, challenges: int, rng_keys=ANCHOR_RING_N) -> dict:
    """Time plot_v3/commit_v3/prove_v3/verify_v3 over the ring keys × repeats (A7 pattern)."""
    t_plot, t_prove, t_verify = [], [], []
    proof_bytes_seen: list[int] = []
    for j in range(rng_keys):
        pk = _pk_for(j)
        rng = random.Random(SEED ^ (node_id_from_pk(pk) & ((1 << 64) - 1)))
        for _ in range(repeats):
            t0 = time.perf_counter(); labels = plot_v3(pk, N, delta)
            t_plot.append((time.perf_counter() - t0) * 1e3)
            levels, root = commit_v3(labels)
            prove_s, verify_s = [], []
            for _c in range(challenges):
                i = rng.randrange(1, N)
                t0 = time.perf_counter(); proof = prove_v3(levels, pk, N, delta, i)
                prove_s.append((time.perf_counter() - t0) * 1e3)
                t0 = time.perf_counter(); ok = verify_v3(root, pk, N, delta, i, proof)
                verify_s.append((time.perf_counter() - t0) * 1e3)
                assert ok, f"verify_v3 failed at N={N} delta={delta} i={i}"
                proof_bytes_seen.append(sum(len(lbl) + 32 * len(path)
                                            for (lbl, path) in proof.values()))
            t_prove.append(statistics.fmean(prove_s))
            t_verify.append(statistics.fmean(verify_s))
    return {
        "proof_size_bytes": int(statistics.median(proof_bytes_seen)),
        "prover_ms": _mean(t_prove),
        "verifier_ms": _mean(t_verify),
        "plot_time_s": _mean(t_plot) / 1e3,
        "plot_size_gib": (32 * N) / (1024 ** 3),
    }


# ---------------------------------------------------------------------------------------
# source=extrapolated_v3 — fair same-scale row at the thesis plot N (≈100 GiB).
# ---------------------------------------------------------------------------------------
def _load_native_plot_times() -> dict:
    """{delta: plot_time_100GiB_native_s} from committed phase1/results/results_plot_extrap_v3.csv."""
    out: dict[int, float] = {}
    if PLOT_EXTRAP_CSV.exists():
        for r in csv.DictReader(open(PLOT_EXTRAP_CSV)):
            try:
                out[int(r["delta"])] = float(r["plot_time_100GiB_native_s"])
            except (KeyError, ValueError):
                pass
    return out


# ---------------------------------------------------------------------------------------
# row builder + CSV (C-suite idiom).
# ---------------------------------------------------------------------------------------
FIELDS = ["scheme", "parameter", "proof_size_bytes", "prover_ms", "verifier_ms",
          "plot_time", "plot_size", "source", "scale", "note"]


def v3_row(source, scale, delta, proof_b, prover_ms, verifier_ms, plot_s, plot_gib, note) -> dict:
    return {
        "scheme": "proposed_v3", "parameter": f"delta={delta}",
        "proof_size_bytes": proof_b, "prover_ms": prover_ms, "verifier_ms": verifier_ms,
        "plot_time": plot_s, "plot_size": plot_gib,
        "source": source, "scale": scale, "note": note,
    }


def chia_row() -> dict:
    c = CHIA_K32
    return {
        "scheme": "chia", "parameter": c["parameter"],
        "proof_size_bytes": c["proof_size_bytes"], "prover_ms": c["prover_ms"],
        "verifier_ms": c["verifier_ms"], "plot_time": c["plot_time_s"],
        "plot_size": c["plot_size_gib"], "source": "chia_cited",
        "scale": "k=32 (101.4 GiB)", "note": c["note"],
    }


def _fmt(v) -> str:
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.6f}"
    return str(v)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def write_csv(rows: list[dict]) -> None:
    order = {"measured_v3": 0, "extrapolated_v3": 1, "chia_cited": 2}
    rows_sorted = sorted(rows, key=lambda r: (order.get(r["source"], 9),
                                              str(r["parameter"])))
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows_sorted:
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# ---------------------------------------------------------------------------------------
# Plot: (1) proof size vs in-degree δ (v3 measured + thesis-scale) with Chia's 256 B line;
# (2) plot/prove/verify at matched ~100 GiB scale — v3 (δ=2) vs Chia k=32, log-y.
# ---------------------------------------------------------------------------------------
def make_plot(rows: list[dict]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    V3, CHIA = "#2a78d6", "#8a1c5a"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    def by(source):
        d = {}
        for r in rows:
            if r["source"] == source:
                d[int(str(r["parameter"]).split("=")[1])] = r
        return d
    meas, extr = by("measured_v3"), by("extrapolated_v3")
    chia = next(r for r in rows if r["source"] == "chia_cited")

    # --- panel 1: proof size vs δ ---
    ax = axes[0]
    ds = sorted(meas)
    if meas:
        ax.plot(ds, [meas[d]["proof_size_bytes"] for d in ds], marker="o", ms=5, lw=1.4, ls="--",
                color=V3, alpha=0.65, label=f"v3 measured (2^{ANCHOR_LOG2})")
    if extr:
        ax.plot(sorted(extr), [extr[d]["proof_size_bytes"] for d in sorted(extr)],
                marker="s", ms=6, lw=2.0, color=V3,
                label=f"v3 thesis N ({REAL_PLOT_N/1e9:.2f}e9)")
    ax.axhline(chia["proof_size_bytes"], color=CHIA, lw=2.0,
               label=f"Chia k=32 ({chia['proof_size_bytes']} B)")
    ax.set_yscale("log")
    ax.set_xlabel("DRG in-degree δ"); ax.set_ylabel("proof size (bytes)")
    ax.set_xticks(ds if ds else DELTAS)
    ax.set_title("Proof size — v3 grows with δ; Chia is a flat 256 B")
    ax.legend(frameon=False, fontsize=8, loc="center left")

    # --- panel 2: plot / prove / verify at ~100 GiB (v3 δ=2 thesis vs Chia k=32) ---
    ax = axes[1]
    v3t = extr.get(2, {})
    metrics = ["plot_time\n(s)", "prover\n(ms)", "verifier\n(ms)"]
    v3_vals = [v3t.get("plot_time", float("nan")),
               v3t.get("prover_ms", float("nan")), v3t.get("verifier_ms", float("nan"))]
    chia_vals = [chia["plot_time"], chia["prover_ms"], chia["verifier_ms"]]
    x = range(len(metrics)); w = 0.38
    floor = 1e-4   # so a ~tens-of-µs bar is visible on the log axis

    def _bar(xs, vals, off, color, lab):
        hv = [max(v, floor) if (isinstance(v, (int, float)) and not math.isnan(v)) else floor
              for v in vals]
        ax.bar([xi + off for xi in xs], hv, width=w, color=color, label=lab, alpha=0.9)
        for xi, v in zip(xs, vals):
            txt = "n/p" if (isinstance(v, float) and math.isnan(v)) else (
                f"{v:.3g}" if v >= 0.01 else f"{v*1e3:.2g}µs")
            ax.text(xi + off, max(v, floor) * 1.15 if not (isinstance(v, float) and math.isnan(v))
                    else floor * 1.15, txt, ha="center", va="bottom", fontsize=7, color=MUTED)
    _bar(x, v3_vals, -w / 2, V3, "v3 (δ=2, thesis N)")
    _bar(x, chia_vals, w / 2, CHIA, "Chia (k=32)")
    ax.set_yscale("log")
    ax.set_xticks(list(x)); ax.set_xticklabels(metrics)
    ax.set_ylabel("cost (log scale; s or ms as labelled)")
    ax.set_title("Cost at matched ~100 GiB (v3 ≈ Chia k=32)")
    ax.legend(frameon=False, fontsize=8, loc="upper right")
    ax.text(0.01, 0.02, "Chia verifier: no published ms (n/p)", transform=ax.transAxes,
            fontsize=6.5, color=MUTED)

    fig.suptitle("C4 — concrete PoSpace costs: proposed v3 (measured) vs Chia (cited)",
                 y=1.03, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
# self-test (deterministic; no Docker) — b2/b5/c2/c3 lettered-check convention.
# ---------------------------------------------------------------------------------------
def _self_test() -> int:
    ok = True
    rng = random.Random(SEED)

    # (a) proof-size: measured == analytic == (1+δ)·(1+log₂N)·32 at a small N
    N = 1 << 14
    worst = 0
    for delta in DELTAS:
        pk = _pk_for(0)
        levels, root = commit_v3(plot_v3(pk, N, delta))
        got = []
        for _ in range(8):
            i = rng.randrange(1, N)
            proof = prove_v3(levels, pk, N, delta, i)
            got.append(sum(len(lbl) + 32 * len(path) for (lbl, path) in proof.values()))
        # a full-cone proof opens exactly 1+δ nodes; low-index edge nodes may open fewer, so the
        # formula is the max (the committed proof_bytes_max in bench_v3) — check the maximum matches.
        worst = max(worst, abs(max(got) - proof_size_formula(N, delta)))
    a_ok = worst == 0
    ok &= a_ok
    print(f"  (a) proof size max == (1+δ)(1+log₂N)·32: max|Δ|={worst} B  [{'ok' if a_ok else 'OFF'}]")

    # (b) prove/verify round-trip: honest proof verifies True, a 1-byte tamper verifies False
    N, delta = 1 << 12, 2
    pk = _pk_for(1)
    levels, root = commit_v3(plot_v3(pk, N, delta))
    i = rng.randrange(1, N)
    proof = prove_v3(levels, pk, N, delta, i)
    honest = verify_v3(root, pk, N, delta, i, proof)
    lbl, path = proof[i]
    proof[i] = (bytes([lbl[0] ^ 1]) + lbl[1:], path)      # flip one bit of node i's label
    tampered = verify_v3(root, pk, N, delta, i, proof)
    b_ok = honest and not tampered
    ok &= b_ok
    print(f"  (b) verify_v3 honest={honest} tampered={tampered}  [{'ok' if b_ok else 'OFF'}]")

    # (c) every chia_cited row carries a non-empty source URL in note
    cr = chia_row()
    c_ok = "http" in cr["note"] and cr["source"] == "chia_cited"
    ok &= c_ok
    print(f"  (c) Chia row cites a source URL  [{'ok' if c_ok else 'OFF'}]")

    # (d) output CSV schema carries the 7 issue-required columns, in order
    required = ["scheme", "parameter", "proof_size_bytes", "prover_ms", "verifier_ms",
                "plot_time", "plot_size"]
    d_ok = FIELDS[:len(required)] == required
    ok &= d_ok
    print(f"  (d) CSV has the 7 issue columns in order  [{'ok' if d_ok else 'OFF'}]")

    # (e) thesis-scale plot times load from the committed extrapolation CSV
    nat = _load_native_plot_times()
    e_ok = all(d in nat and nat[d] > 0 for d in DELTAS)
    ok &= e_ok
    print(f"  (e) native plot times from results_plot_extrap_v3.csv: "
          f"{ {d: round(nat.get(d, float('nan')), 1) for d in DELTAS} }  [{'ok' if e_ok else 'OFF'}]")

    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="C4 proof size & prover/verifier time vs Chia (#53).")
    ap.add_argument("--self-test", action="store_true", help="deterministic checks, no Docker")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--anchor-log2", type=int, default=ANCHOR_LOG2, help="measured-anchor size 2^k")
    ap.add_argument("--repeats", type=int, default=ANCHOR_REPEATS)
    ap.add_argument("--challenges", type=int, default=ANCHOR_CHALLENGES)
    ap.add_argument("--deltas", default=",".join(str(d) for d in DELTAS))
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()

    if args.self_test:
        return _self_test()

    deltas = [int(d) for d in args.deltas.split(",") if d]
    anchor_N = 1 << args.anchor_log2
    native_plot = _load_native_plot_times()

    print(f"C4 proof metrics (v3 measured vs Chia cited) — seed={args.seed}, "
          f"CHAIN_RATE={CHAIN_RATE/1e6:.2f} MH/s")
    print(f"  measured anchor N=2^{args.anchor_log2}  deltas={deltas}  "
          f"thesis N=REAL_PLOT_N={REAL_PLOT_N:,} (node default plot={NODE_DEFAULT_PLOT_N:,}, "
          f"δ={NODE_DEFAULT_DELTA})")

    rows: list[dict] = []

    print("\n== source=measured_v3 (fresh anchor, A7 timing recipe) ==")
    anchor = {}
    for delta in deltas:
        m = measure_anchor(anchor_N, delta, args.repeats, args.challenges)
        anchor[delta] = m
        rows.append(v3_row(
            "measured_v3", f"2^{args.anchor_log2} (toy)", delta,
            m["proof_size_bytes"], m["prover_ms"], m["verifier_ms"],
            m["plot_time_s"], m["plot_size_gib"],
            (f"MEASURED over {ANCHOR_RING_N} ring keys × {args.repeats} reps × {args.challenges} "
             f"challenges; recipe = experiments/a7_admission.py; cross-cite results/A7_admission.csv")))
        print(f"    δ={delta}: proof {m['proof_size_bytes']} B | prove {m['prover_ms']*1e3:7.2f} µs "
              f"| verify {m['verifier_ms']*1e3:7.2f} µs | plot {m['plot_time_s']*1e3:8.2f} ms "
              f"| plot_size {m['plot_size_gib']*1024:.2f} MiB")

    print("\n== source=extrapolated_v3 (fair same-scale, thesis N ≈ 100 GiB) ==")
    for delta in deltas:
        proof_b = proof_size_formula(REAL_PLOT_N, delta)
        plot_s = native_plot.get(delta, float("nan"))
        a = anchor.get(delta, {})
        rows.append(v3_row(
            "extrapolated_v3", f"N={REAL_PLOT_N} (~100 GiB)", delta,
            proof_b, a.get("prover_ms", float("nan")), a.get("verifier_ms", float("nan")),
            plot_s, 100.0,
            (f"proof = (1+δ)(1+⌈log₂N⌉)·32 B exact [phase1/FIX_A.md §4]; "
             f"plot_time = native-rate floor [phase1/results/results_plot_extrap_v3.csv]; "
             f"plot_size = 100 GiB labels (≈200 GiB with Merkle tree); "
             f"prove/verify size-independent to first order, carried from the 2^{args.anchor_log2} "
             f"anchor (FLAG: toy-scale timing, +O(log N) Merkle hashes ≪ network RTT)")))
        print(f"    δ={delta}: proof {proof_b} B ({proof_b/1024:.2f} KiB) | "
              f"plot(native) {plot_s:7.1f} s | plot_size 100 GiB | "
              f"prove {a.get('prover_ms', float('nan'))*1e3:6.2f} µs "
              f"verify {a.get('verifier_ms', float('nan'))*1e3:6.2f} µs (carried)")

    print("\n== source=chia_cited (k=32, published) ==")
    cr = chia_row()
    rows.append(cr)
    print(f"    k=32: proof {cr['proof_size_bytes']} B | prover {cr['prover_ms']:.0f} ms (HDD lookup) "
          f"| verifier n/p (sub-ms) | plot ~{cr['plot_time']:.0f} s | plot_size {cr['plot_size']} GiB")

    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)

    print("\n" + "=" * 96)
    v3 = next(r for r in rows if r["source"] == "extrapolated_v3" and r["parameter"] == "delta=2")
    print("BOTTOM LINE (fair ~100 GiB comparison, v3 δ=2 vs Chia k=32):")
    print(f"  proof size : v3 {v3['proof_size_bytes']} B ({v3['proof_size_bytes']/1024:.2f} KiB)  "
          f"vs Chia 256 B  → v3 ~{v3['proof_size_bytes']/256:.0f}× larger (cost of DRG+Merkle)")
    print(f"  plot time  : v3 {v3['plot_time']:.0f} s (native)  vs Chia ~300 s high-end  "
          f"→ comparable")
    print(f"  prove/verify: v3 ~tens of µs in-RAM (no disk)  vs Chia ~640 ms seek-bound lookup "
          f"/ verify near-instant")
    print("  → v3 trades LARGER proofs for in-RAM (seek-free) proving; see C5 for the full table "
          "and the 'what is lost by gaining efficiency' discussion.")
    print("=" * 96)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
