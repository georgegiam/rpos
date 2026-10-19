#!/usr/bin/env python3
"""Issue #50 [C1] — Final partial-storage (retention) attack on the frozen v3 DRG scheme
(Phase 8, examiner point (i)).

C1 produces the DEFINITIVE time-space trade-off for the PROPOSED scheme: "how much storage can a
cheater discard and still respond within the timeout δ?" It re-runs the Phase 1 retention attack on
the frozen v3 DRG (phase1/pospace_drg.py + phase1/drg.py), sweeps the storage the cheater keeps,
and extrapolates the measured back-cone recompute to thesis scale N = 3,355,443,200.

The retention-attack PHYSICS already live in frozen phase1/attack_v3_retain.py (the DRG back-cone
closure) and the thesis-scale extrapolation in phase1/delta_separation_drg.py. Per CLAUDE.md §2
those are FROZEN (import/read only, never modified), and their sweep only lands on powers-of-two
strides {100, 75, 37.5, 18.75, ...}% of the tree — which do NOT hit the round fractions issue #50
asks for. So C1 is a new experiments-suite driver that IMPORTS those primitives and re-samples at
the requested storage fractions, writing the top-level deliverables.

HEADLINE AXIS = LABEL FRACTION (fraction of the plot's N labels the cheater keeps; "discard X% of
the plot"). A uniform retained mask hits {1, 5, 10, 25, 50, 75, 100}% exactly. We also report the
total-tree storage fraction (labels + internal Merkle nodes) so the numbers line up with FIX_A's
"ρ=0.5 labels → 0.75 storage" convention.

WHAT IS MEASURED, per (N, δ_indegree, label-fraction), over random challenges:
  * back_cone_hashes — the DRG back-cone the cheater must recompute to answer (follow parents back
    until they bottom out at a retained label); this is the Fix-A cost. Median & p99.
  * recompute_time_s = back_cone_hashes / 20.36 MH/s (the measured native single-core SHA-256 rate,
    CLAUDE.md §5) — the modeled wall-clock a cheater needs; median & p99.
  * depth — the back-cone critical path (sequential work even with unlimited cores) → parallel floor.
  * success_vs_δ — 1 iff recompute_time ≤ δ (the cheater answers in time), for δ ∈ {1, 2, 5} s.
Counts are structural/deterministic (graph traversal, no hashing), so the sweep is exact; a
power-of-two subset is ALSO really plotted + reconstructed + checked with verify_v3 (source=
validated), and one real recompute is timed (source=wallclock_anchor) to anchor the model.

THESIS-SCALE EXTRAPOLATION (source=extrapolated, N=REAL_PLOT_N): reuse the delta_separation model —
φ(δ, ρ) = median over the measured N of back_cone_hashes/N (shown ~flat in N), so the thesis-scale
recompute is φ·N / rate. Back-cone caveat (stated in C1_NOTES.md): φ is taken flat across the
measured 2^18–2^22 and applied ~800× beyond it, relying on DRSample's asymptotic depth-robustness,
not a re-proof; the unlimited-core parallel floor ≈ (N/log2 N)/rate makes the loosest δ=5 s marginal
and is reported as a caveated sensitivity, not the verdict basis. In-degree δ / target
depth-robustness / stacked-DRG still await cryptographer sign-off (CLAUDE.md, Phase 1 "Open").

Touches no frozen artifact (rpos/rpos.py, phase1/*, node/* imported/read only). Fixed seed 20260919.

Run:  python3 experiments/c1_retention.py                    # full sweep -> CSV + PNG + stdout
      python3 experiments/c1_retention.py --no-plot          # table only
      python3 experiments/c1_retention.py --quick            # drop N=2^22 (fast iteration)
      python3 experiments/c1_retention.py --fractions 1,10,50,100 --deltas 2
"""
from __future__ import annotations

import argparse
import csv
import math
import random
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
OUT_CSV = RESULTS / "C1_retention_attack.csv"
OUT_FIG = RESULTS / "fig_C1_retention.png"

# phase1/ holds the frozen retention-attack physics; it must be importable both as the top-level
# package root (for the sibling `pospace`/`drg` imports inside those modules) and the repo root.
for p in (REPO_ROOT, REPO_ROOT / "phase1"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# frozen primitives — imported, never copied (CLAUDE.md §2). Importing runs no run()/_test().
import attack_v3_retain as av3                                   # noqa: E402
from attack_v3_retain import (                                   # noqa: E402
    parent_table, backcone_mask, backcone_depth, honest_bytes, metric_challenges,
)
from pospace_drg import plot_v3, commit_v3, verify_v3, _label    # noqa: E402
from pospace import node                                         # noqa: E402
from drg import parents                                          # noqa: E402

# thesis plot size — the constant the node actually admits with (node/pospace_admission.py:52).
try:
    from node.pospace_admission import REAL_PLOT_N               # noqa: E402
except Exception:                                                # keep the plotter dependency-light
    REAL_PLOT_N = 3_355_443_200

# ---------------------------------------------------------------------------------------
# frozen C1 workload
# ---------------------------------------------------------------------------------------
SEED = 20260919                                   # frozen repo seed (CLAUDE.md §2; phase1 used 1)
NS = [1 << 18, 1 << 20, 1 << 22]                  # measured sizes (the Phase-1 grid → φ audit)
DELTAS = [2, 4, 8]                                # DRG in-degree; 2 = node default = headline
FRACTIONS = [0.01, 0.05, 0.10, 0.25, 0.50, 0.75, 1.00]   # label fractions kept (issue #50)
RESP_DELTAS = [1.0, 2.0, 5.0]                     # response timeouts (s): 2 = test; 5 = loosest thesis
DEPTH_BUDGET = 300_000                            # exact critical-path depth only up to this cone size
VERIFY_MAX_N = 1 << 20                            # really plot+reconstruct+verify_v3 at/below this N
VERIFY_CHALLENGES = 5                             # real round-trip checks per verifiable anchor


# --- measured native single-core SHA-256 rate (repo convention; CLAUDE.md §5) ---
def _load_chain_rate(default_hs: float = 20_363_000.0) -> float:
    """hashes/s (native, single core) from phase1/results/chainrate.csv — matches a7/b2/bench_v3."""
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


def _pct(xs, q):
    """Nearest-rank percentile (q in [0,1]); mirrors attack_v3_retain.pct."""
    if not xs:
        return float("nan")
    s = sorted(xs)
    k = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return s[k]


# ---------------------------------------------------------------------------------------
# storage model — LABEL fraction (headline) and the derived TOTAL-TREE fraction (FIX_A axis).
# ---------------------------------------------------------------------------------------
def retained_mask(N: int, label_frac: float) -> np.ndarray:
    """Keep round(label_frac·N) labels, evenly spaced. General (any fraction incl. 75%); for the
    1/integer fractions this coincides with the frozen 'every s-th label' stride."""
    m = max(1, min(N, int(round(label_frac * N))))
    mask = np.zeros(N, dtype=bool)
    if m >= N:
        mask[:] = True
    else:
        idx = np.unique(np.round(np.linspace(0, N - 1, m)).astype(np.int64))
        mask[idx] = True
    return mask


def total_store_fraction(N: int, retained_count: int) -> float:
    """Fraction of the full honest Merkle tree (labels + internal nodes). Generalises
    attack_v3_retain.storage_bytes to any retained count: the cheater keeps the retained leaves plus
    every internal node at/above the retained granularity (gap ≈ N/retained). Reproduces FIX_A at
    powers of two: ρ=0.5 labels → 0.75 storage, ρ=0.25 → 0.375, etc."""
    if retained_count >= N:
        return 1.0
    logN = N.bit_length() - 1
    L = max(1, round(math.log2(N / retained_count)))
    retained = 32 * retained_count
    upper = 32 * sum(N >> l for l in range(L, logN + 1))
    return (retained + upper) / honest_bytes(N)


# ---------------------------------------------------------------------------------------
# one config: back-cone size & depth over random challenges (any retained mask).
# base targets = the opened nodes (challenge i + its DRG parents); we measure the DRG recompute
# the cheater cannot avoid. (The frozen attack additionally folds a negligible lower-Merkle rebuild
# term; at the small-storage regime that governs the verdict it is <1% of the back-cone — see NOTES.)
# ---------------------------------------------------------------------------------------
def measure_config(N, delta, pk, mask, tab, rng, n_chal):
    rec, depths = [], []
    saturated = False
    for _ in range(n_chal):
        i = rng.randrange(1, N)
        opened = np.array([i] + parents(i, pk, delta), dtype=np.int64)
        seen = backcone_mask(opened, mask, tab)
        n_labels = int(seen.sum())
        rec.append(n_labels)
        if n_labels <= DEPTH_BUDGET:
            depths.append(backcone_depth(seen, tab))
        else:
            saturated = True
    return rec, depths, saturated


# ---------------------------------------------------------------------------------------
# real reconstruction + verify_v3 at a power-of-two stride (reuses the frozen validator), and a
# timed recompute to anchor the modeled native wall-clock.
# ---------------------------------------------------------------------------------------
def validate_anchor(N, delta, s, pk, tab, rng):
    """Really plot, keep every s-th label, reconstruct the rest, and check verify_v3. Returns
    (pass_rate, trials). Reuses frozen attack_v3_retain.validate_config verbatim (sets its PK)."""
    labels = plot_v3(pk, N, delta)
    levels, _ = commit_v3(labels)
    ret_labels = {int(m): node(levels[0], int(m)) for m in range(0, N, s)}
    av3.PK = pk                                   # frozen validate_config reads the module global
    passes, trials = av3.validate_config(N, delta, s, tab, levels, ret_labels, rng)
    return (passes / trials if trials else float("nan")), trials, levels


def time_real_recompute(N, delta, s, pk, tab, levels, rng):
    """Time a genuine back-cone recompute for one feasible challenge (Python), to anchor the
    native-rate model. Returns (n_labels, wall_s, python_mh_s) or None if no small-enough cone."""
    mask = np.zeros(N, dtype=bool)
    mask[np.arange(0, N, s)] = True
    ret_labels = {int(m): node(levels[0], int(m)) for m in range(0, N, s)}
    for _ in range(40):
        i = rng.randrange(1, N)
        opened = np.array([i] + parents(i, pk, delta), dtype=np.int64)
        seen = backcone_mask(opened, mask, tab)
        n = int(seen.sum())
        if 2000 <= n <= 150_000:                  # bounded but non-trivial
            known = dict(ret_labels)
            order = np.nonzero(seen)[0]
            t0 = time.perf_counter()
            for j in order:
                ps = [int(p) for p in tab[j] if p >= 0]
                known[int(j)] = _label(pk, int(j), [known[p] for p in ps])
            wall = time.perf_counter() - t0
            return n, wall, (n / wall) / 1e6 if wall > 0 else float("nan")
    return None


# ---------------------------------------------------------------------------------------
# row builders.
# ---------------------------------------------------------------------------------------
def _succ_cols(t_seq_s: float) -> dict:
    return {f"success_{int(d)}s": (1 if (not math.isnan(t_seq_s) and t_seq_s <= d) else 0)
            for d in RESP_DELTAS}


def measured_row(N, delta, label_frac, mask, rec, dep, sat) -> dict:
    rc = int(mask.sum())
    rec_med, rec_p99 = int(statistics.median(rec)), int(_pct(rec, 0.99))
    dep_med = int(statistics.median(dep)) if dep else -1
    t_med = rec_med / CHAIN_RATE
    row = dict(
        source="measured", N=N, log2N=N.bit_length() - 1, delta=delta,
        label_frac_pct=label_frac * 100.0, retained_labels=rc,
        total_store_frac=total_store_fraction(N, rc),
        back_cone_hashes_median=rec_med, back_cone_hashes_p99=rec_p99,
        depth_median=dep_med, saturated=int(sat),
        recompute_time_s_median=t_med, recompute_time_s_p99=rec_p99 / CHAIN_RATE,
        phi=rec_med / N,
        par_floor_s=(dep_med / CHAIN_RATE) if dep_med >= 0 else float("nan"),
        pass_rate=float("nan"), pass_validated=0,
        challenges=len(rec), note="")
    row.update(_succ_cols(t_med))
    return row


def extrapolated_row(delta, label_frac, phi, per_n) -> dict:
    N = REAL_PLOT_N
    logN = math.ceil(math.log2(N))
    bc = phi * N
    t_seq = bc / CHAIN_RATE
    par_floor = (N / logN) / CHAIN_RATE                       # DRSample Ω(N/log N) theory anchor
    spread = ",".join(f"2^{e}:{per_n.get(1 << e, float('nan')):.3f}" for e in (18, 20, 22))
    row = dict(
        source="extrapolated", N=N, log2N=logN, delta=delta,
        label_frac_pct=label_frac * 100.0, retained_labels=int(round(label_frac * N)),
        total_store_frac=total_store_fraction(N, int(round(label_frac * N))),
        back_cone_hashes_median=int(bc), back_cone_hashes_p99=float("nan"),
        depth_median=-1, saturated=1 if phi >= 0.4 else 0,
        recompute_time_s_median=t_seq, recompute_time_s_p99=float("nan"),
        phi=phi, par_floor_s=par_floor,
        pass_rate=float("nan"), pass_validated=0,
        challenges=0, note=f"phi flat in N [{spread}]; par_floor=unlimited-core sensitivity")
    row.update(_succ_cols(t_seq))
    return row


# ---------------------------------------------------------------------------------------
# CSV.
# ---------------------------------------------------------------------------------------
FIELDS = ["source", "N", "log2N", "delta", "label_frac_pct", "retained_labels",
          "total_store_frac", "back_cone_hashes_median", "back_cone_hashes_p99",
          "depth_median", "saturated", "recompute_time_s_median", "recompute_time_s_p99",
          "phi", "par_floor_s", "success_1s", "success_2s", "success_5s",
          "pass_rate", "pass_validated", "challenges", "note"]


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
    order = {"measured": 0, "validated": 1, "wallclock_anchor": 2, "extrapolated": 3}
    def key(r):
        return (order.get(r["source"], 9), r["delta"], r["N"], -r.get("label_frac_pct", 0))
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=key):
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# ---------------------------------------------------------------------------------------
# Plot: (1) the definitive trade-off — recompute time vs storage kept, measured + thesis-scale,
# with the δ timeout lines; (2) the back-cone fraction φ vs storage (saturation toward ~0.45).
# ---------------------------------------------------------------------------------------
def make_plot(rows: list[dict]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    shades = {2: "#2a78d6", 4: "#e08a1e", 8: "#8a1c5a"}
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    def series(source, delta, xfield, yfield, N=None):
        rs = [r for r in rows if r["source"] == source and r["delta"] == delta
              and (N is None or r["N"] == N)]
        rs.sort(key=lambda r: r[xfield])
        return [r[xfield] for r in rs], [r[yfield] for r in rs]

    measured_N = max((r["N"] for r in rows if r["source"] == "measured"), default=NS[-1])

    # --- panel 1: recompute time vs storage kept ---
    ax = axes[0]
    for delta in sorted(shades):
        xm, ym = series("measured", delta, "label_frac_pct", "recompute_time_s_median", N=measured_N)
        if xm:
            ax.plot(xm, ym, marker="o", ms=4, lw=1.3, ls="--", color=shades[delta], alpha=0.55,
                    label=f"measured 2^{measured_N.bit_length()-1}, δ={delta}")
        xe, ye = series("extrapolated", delta, "label_frac_pct", "recompute_time_s_median")
        if xe:
            ax.plot(xe, ye, marker="s", ms=5, lw=2.0, color=shades[delta],
                    label=f"thesis N={REAL_PLOT_N/1e9:.2f}e9, δ={delta}")
    for d in RESP_DELTAS:
        ax.axhline(d, color=MUTED, lw=0.9, ls=":")
        ax.text(1.05, d, f"δ={d:g}s", fontsize=7, color=MUTED, va="bottom")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.invert_xaxis()                              # discard more storage → rightward
    ax.set_xlabel("storage kept (% of plot labels)"); ax.set_ylabel("recompute time (s)")
    ax.set_title(f"Retention trade-off (v3 DRG) — rate {CHAIN_RATE/1e6:.1f} MH/s")
    ax.legend(frameon=False, fontsize=7, loc="lower left")

    # --- panel 2: back-cone fraction φ vs storage kept ---
    ax = axes[1]
    for delta in sorted(shades):
        xm, ym = series("measured", delta, "label_frac_pct", "phi", N=measured_N)
        if xm:
            ax.plot(xm, ym, marker="o", ms=4, lw=1.7, color=shades[delta], label=f"δ={delta}")
    ax.set_xscale("log")
    ax.invert_xaxis()
    ax.set_xlabel("storage kept (% of plot labels)")
    ax.set_ylabel("back-cone fraction φ = recompute / N")
    ax.set_title(f"Recompute saturates toward ~½·N (N=2^{measured_N.bit_length()-1})")
    ax.legend(frameon=False, fontsize=9, title="in-degree")

    fig.suptitle("C1 — final partial-storage (retention) attack on the proposed v3 DRG PoSpace",
                 y=1.03, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="C1 retention attack on frozen v3 DRG (issue #50).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--quick", action="store_true", help="drop N=2^22 (fast iteration)")
    ap.add_argument("--no-validate", action="store_true", help="skip real verify_v3 anchors")
    ap.add_argument("--fractions", default=",".join(f"{int(f*100)}" for f in FRACTIONS),
                    help="comma list of label fractions kept, in percent")
    ap.add_argument("--deltas", default=",".join(str(d) for d in DELTAS),
                    help="comma list of DRG in-degrees")
    ap.add_argument("--sizes", default="", help="override measured sizes (comma log2 list)")
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()

    fracs = [int(x) / 100.0 for x in args.fractions.split(",") if x]
    deltas = [int(d) for d in args.deltas.split(",") if d]
    if args.sizes:
        ns = [1 << int(e) for e in args.sizes.split(",") if e]
    else:
        ns = [n for n in NS if not (args.quick and n == (1 << 22))]

    print(f"C1 retention attack (v3 DRG) — seed={args.seed}, CHAIN_RATE={CHAIN_RATE/1e6:.2f} MH/s")
    print(f"  measured N={[n.bit_length()-1 for n in ns]} (log2)  deltas={deltas}  "
          f"label-fractions={[f'{f*100:g}%' for f in fracs]}")
    print(f"  thesis N=REAL_PLOT_N={REAL_PLOT_N:,}  response δ grid={RESP_DELTAS}s")

    rng = random.Random(args.seed)
    rows: list[dict] = []
    phi_acc: dict[tuple, dict] = defaultdict(dict)        # (delta, frac_pct) -> {N: phi}

    print("\n== source=measured (DRG back-cone over random challenges) ==")
    for N in ns:
        logN = N.bit_length() - 1
        pk = bytes(rng.getrandbits(8) for _ in range(33))
        nchal = metric_challenges(N)
        for delta in deltas:
            print(f"  building DRG parent table N=2^{logN} δ={delta} ...", flush=True)
            tab = parent_table(N, pk, delta)
            for frac in fracs:
                mask = retained_mask(N, frac)
                rec, dep, sat = measure_config(N, delta, pk, mask, tab, rng, nchal)
                row = measured_row(N, delta, frac, mask, rec, dep, sat)
                rows.append(row)
                phi_acc[(delta, round(frac * 100))][N] = row["phi"]
                print(f"    δ={delta} N=2^{logN} keep {frac*100:5.1f}% labels "
                      f"({row['total_store_frac']*100:5.1f}% tree) | rec {row['back_cone_hashes_median']:>9d} h"
                      f"{' SAT' if sat else '   '} | depth {row['depth_median']:>7} | "
                      f"seq {row['recompute_time_s_median']*1e3:9.3f} ms", flush=True)

            # real verify_v3 anchors at power-of-two strides (where Merkle blocks are exact)
            if not args.no_validate and N <= VERIFY_MAX_N:
                for s in (2, 4, 8, 16):
                    lf = 1.0 / s
                    pr, trials, levels = validate_anchor(N, delta, s, pk, tab, rng)
                    vr = measured_row(N, delta, lf, retained_mask(N, lf),
                                      *measure_config(N, delta, pk,
                                                       (np.arange(N) % s == 0), tab, rng, nchal))
                    vr["source"] = "validated"
                    vr["pass_rate"] = pr
                    vr["pass_validated"] = 1 if trials else 0
                    vr["note"] = f"every {s}-th label (stride anchor); verify_v3 {pr:.2f}"
                    rows.append(vr)
                    # one timed real recompute to anchor the native-rate model
                    tr = time_real_recompute(N, delta, s, pk, tab, levels, rng)
                    if tr is not None:
                        n_lab, wall, py_mh = tr
                        wa = dict(vr)
                        wa["source"] = "wallclock_anchor"
                        wa["back_cone_hashes_median"] = n_lab
                        wa["recompute_time_s_median"] = n_lab / CHAIN_RATE
                        wa["pass_rate"] = float("nan"); wa["pass_validated"] = 0
                        wa.update(_succ_cols(n_lab / CHAIN_RATE))
                        wa["note"] = (f"REAL recompute: {n_lab} labels in {wall*1e3:.1f} ms Python "
                                      f"({py_mh:.2f} MH/s); modeled native {n_lab/CHAIN_RATE*1e3:.3f} ms")
                        rows.append(wa)
                    print(f"    [anchor] δ={delta} N=2^{logN} s={s} (keep {lf*100:g}%): "
                          f"verify_v3 pass {pr:.2f} ({trials} trials)"
                          + (f", real recompute {tr[0]} h in {tr[1]*1e3:.1f} ms" if tr else ""),
                          flush=True)

    print("\n== source=extrapolated (φ·N / rate at thesis N) ==")
    for delta in deltas:
        for frac in fracs:
            per_n = phi_acc.get((delta, round(frac * 100)), {})
            if not per_n:
                continue
            phi = statistics.median(per_n.values())
            row = extrapolated_row(delta, frac, phi, per_n)
            rows.append(row)
            print(f"  δ={delta} keep {frac*100:5.1f}%: φ={phi:.3f} → {row['back_cone_hashes_median']:,} h "
                  f"→ {row['recompute_time_s_median']:8.2f} s  "
                  f"[≤1s:{row['success_1s']} ≤2s:{row['success_2s']} ≤5s:{row['success_5s']}]")
    par = (REAL_PLOT_N / math.ceil(math.log2(REAL_PLOT_N))) / CHAIN_RATE
    print(f"  (parallel floor, unlimited cores, sensitivity only: ~{par:.2f} s)")

    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
