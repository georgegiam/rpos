#!/usr/bin/env python3
"""Issue #44 [B3] — figure from results/B3_censorship.csv (standalone; matplotlib + stdlib only,
NO node/dnspython imports, so it runs in a minimal plotting env). Produces:

    results/fig_B3_censorship.png

Two panels (style mirrors B1/B2):
  (1) raw-DHT success + end-to-end success vs f, with the resolvable bound 1 − f^s overlaid, plus the
      targeted full-replica-capture point (target raw-DHT → 0, e2e → 100 via fallback);
  (2) fully-censored chunk fraction vs f — measured structural (all s replicas dropped) against the
      analytic f^s — showing censorship needs the WHOLE replica set (contrast B1's 1−(1−f)^s).

Usage (in a venv with matplotlib):  python experiments/plot_b3.py
"""
from __future__ import annotations

import csv
import math
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CSV = REPO_ROOT / "results" / "B3_censorship.csv"
FIG = REPO_ROOT / "results" / "fig_B3_censorship.png"
S = 3


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return float("nan")


def load_rows():
    with open(CSV, newline="") as fh:
        return list(csv.DictReader(fh))


def main() -> int:
    if not CSV.exists():
        print(f"missing {CSV} — run experiments/b3_inproc.py first", file=sys.stderr)
        return 1
    rows = load_rows()
    rnd = sorted((r for r in rows if r["block"] == "random"), key=lambda r: _f(r["realized_f_pct"]))
    tgt = [r for r in rows if r["block"] == "targeted"]

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    EMU, BOUND, STRUCT, TGT, E2E = "#2a78d6", "#8a1c5a", "#c47f16", "#1f8a4c", "#555555"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))
    fs = [i / 200 for i in range(0, 101)]       # 0..0.5

    # --- panel 1: raw-DHT + e2e success vs f, with the resolvable bound ---
    ax = axes[0]
    ax.plot([100 * x for x in fs], [100 * (1 - x ** S) for x in fs],
            lw=1.6, color=BOUND, label="resolvable bound 1−f³ (all s replicas must drop)")
    if rnd:
        ax.errorbar([_f(r["realized_f_pct"]) for r in rnd], [_f(r["raw_dht_success_pct"]) for r in rnd],
                    yerr=[_f(r["raw_dht_success_sd"]) for r in rnd], marker="o", ms=6, lw=1.8,
                    capsize=3, color=EMU, label="raw-DHT success (measured)")
        ax.errorbar([_f(r["realized_f_pct"]) for r in rnd], [_f(r["e2e_success_pct"]) for r in rnd],
                    yerr=[_f(r["e2e_success_sd"]) for r in rnd], marker="s", ms=5, lw=1.4, ls="--",
                    capsize=3, color=E2E, label="end-to-end success (fallback recovers)")
    for t in tgt:
        raw = _f(t["target_raw_dht_success_pct"]); e2e = _f(t["target_e2e_success_pct"])
        if not math.isnan(raw):
            ax.scatter([_f(t["realized_f_pct"])], [raw], marker="*", s=220, color=TGT, zorder=5,
                       label=f"targeted: target raw-DHT (f≈{_f(t['realized_f_pct']):.0f}%)")
            ax.annotate(f"{t.get('target','')}: DHT denied → {raw:.0f}%\n(e2e {e2e:.0f}% via fallback)",
                        (_f(t["realized_f_pct"]), raw), textcoords="offset points",
                        xytext=(10, 10), fontsize=8, color=TGT)
    ax.set_xlabel("adversary fraction f (%)")
    ax.set_ylabel("lookup success (%)")
    ax.set_title("Raw-DHT vs end-to-end success (N=32, s=3)")
    ax.set_ylim(-2, 105)
    ax.legend(frameon=False, fontsize=8, loc="lower left")

    # --- panel 2: fully-censored chunk fraction vs f (needs ALL s replicas) ---
    ax = axes[1]
    ax.plot([100 * x for x in fs], [100 * x ** S for x in fs],
            lw=1.6, color=BOUND, label="analytic f³ (all s replicas malicious)")
    if rnd:
        ax.plot([_f(r["realized_f_pct"]) for r in rnd], [_f(r["structural_censored_pct"]) for r in rnd],
                marker="o", ms=6, lw=1.8, color=STRUCT, label="measured structural (all s dropped)")
    ax.set_xlabel("adversary fraction f (%)")
    ax.set_ylabel("fully-censored chunks (%)")
    ax.set_title("Censorship needs ALL s replicas (vs B1's 1-of-s)")
    ax.set_ylim(bottom=-1)
    ax.legend(frameon=False, fontsize=8, loc="upper left")

    fig.suptitle("B3 — censorship: replication + fallback defeat denial (only f³ of chunks lose the "
                 "DHT path; fallback recovers all)", y=1.02, fontsize=11)
    fig.tight_layout()
    fig.savefig(FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {FIG.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
