#!/usr/bin/env python3
"""Issue #42 [B1] — figure from results/B1_tampering.csv (standalone; matplotlib + stdlib only,
NO node/dnspython imports, so it runs in a minimal plotting env). Produces:

    results/fig_B1_tampering.png

Two panels (style mirrors B3/B4):
  (1) forged-acceptance vs f, with BOTH bounds overlaid — the INTENDED majority bound 3f²−2f³ and
      the ACHIEVED single-replica bound 1−(1−f)³ the implementation exhibits — plus the targeted
      colluding point (one popular chunk forged ~100%);
  (2) end-to-end success vs f (flat → the harm is INTEGRITY, not availability).

Usage (in a venv with matplotlib):  python experiments/plot_b1.py
"""
from __future__ import annotations

import csv
import math
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CSV = REPO_ROOT / "results" / "B1_tampering.csv"
FIG = REPO_ROOT / "results" / "fig_B1_tampering.png"
S = 3


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return float("nan")


def majority_bound(f: float, s: int = S) -> float:
    """P(Binom(s,f) >= ceil((s+1)/2)) — the intended majority-vote bound (3f²−2f³ at s=3)."""
    thresh = s // 2 + 1
    return sum(math.comb(s, k) * f**k * (1 - f) ** (s - k) for k in range(thresh, s + 1))


def single_bound(f: float, s: int = S) -> float:
    """The achieved bound: a single malicious replica suffices (1−(1−f)^s)."""
    return 1.0 - (1.0 - f) ** s


def load_rows():
    with open(CSV, newline="") as fh:
        return list(csv.DictReader(fh))


def main() -> int:
    if not CSV.exists():
        print(f"missing {CSV} — run experiments/b1_inproc.py first", file=sys.stderr)
        return 1
    rows = load_rows()
    rnd = sorted((r for r in rows if r.get("block") == "random"),
                 key=lambda r: _f(r["realized_f_pct"]))
    tgt = [r for r in rows if r.get("block") == "targeted"]

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    EMU, BOUND, STRUCT, TGT = "#2a78d6", "#8a1c5a", "#c47f16", "#1f8a4c"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    # --- panel 1: forged-acceptance vs f, with BOTH bounds overlaid ---
    ax = axes[0]
    fs = [i / 200 for i in range(0, 101)]       # 0..0.5
    ax.plot([100 * f for f in fs], [100 * majority_bound(f) for f in fs],
            lw=1.6, color=BOUND, label="intended majority bound 3f²−2f³ (≥2/3 lie)")
    ax.plot([100 * f for f in fs], [100 * single_bound(f) for f in fs],
            lw=1.6, ls="--", color=STRUCT, label="achieved bound 1−(1−f)³ (≥1/3 lie)")
    if rnd:
        ax.errorbar([_f(r["realized_f_pct"]) for r in rnd],
                    [_f(r["forged_accepted_pct"]) for r in rnd],
                    yerr=[_f(r["forged_accepted_sd"]) for r in rnd], marker="o", ms=6, lw=1.8,
                    capsize=3, color=EMU, label="measured (random placement, in-process)")
    for t in tgt:
        fv, yv = _f(t["realized_f_pct"]), _f(t["forged_accepted_pct"])
        ax.scatter([fv], [yv], marker="*", s=180, color=TGT, zorder=5,
                   label=f"targeted (overall, f≈{fv:.0f}%)")
        tf = _f(t["target_forged_pct"])
        if not math.isnan(tf):
            ax.annotate(f"target chunk\nforged {tf:.0f}%", (fv, yv),
                        textcoords="offset points", xytext=(8, 8), fontsize=8, color=TGT)
    ax.set_xlabel("adversary fraction f (%)")
    ax.set_ylabel("forged answers accepted (%)")
    ax.set_title("Forged-acceptance vs f, with majority-vote bound (N=32, s=3)")
    ax.set_ylim(bottom=-2)
    ax.legend(frameon=False, fontsize=8, loc="upper left")

    # --- panel 2: end-to-end success vs f (flat → integrity harm, not availability) ---
    ax = axes[1]
    if rnd:
        ax.errorbar([_f(r["realized_f_pct"]) for r in rnd],
                    [_f(r["success_rate_pct"]) for r in rnd],
                    yerr=[_f(r["success_sd"]) for r in rnd], marker="o", ms=6, lw=1.8,
                    capsize=3, color=EMU, label="DNS success rate")
    ax.set_xlabel("adversary fraction f (%)")
    ax.set_ylabel("end-to-end success (%)")
    ax.set_title("Success rate vs f (flat → harm is integrity, not availability)")
    ax.set_ylim(0, 105)
    ax.legend(frameon=False, fontsize=9, loc="lower left")

    fig.suptitle("B1 — tampering / cache poisoning: forged-acceptance vs the majority-vote bound",
                 y=1.02, fontsize=12)
    fig.tight_layout()
    fig.savefig(FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {FIG.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
