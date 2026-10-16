#!/usr/bin/env python3
"""Issue #45 [B4] — figure from results/B4_eclipse.csv (standalone; matplotlib + stdlib only,
NO node/dnspython imports, so it runs in a minimal plotting env). Produces:

    results/fig_B4_eclipse.png

Two panels (style mirrors B1/B2/B3):
  (1) raw-DHT lookup success + end-to-end success vs f, with the honest control at f=0 and the
      targeted one-misrouter eclipse point (victim's raw-DHT -> 0, e2e -> 100 via fallback);
  (2) eclipse decomposition vs f — routing-eclipsed (lookups misrouted to the wrong owner) falls to
      DHT-denied (the s-replica read finds nothing; replication's successor overlap rescues the gap)
      falls again to the measured Zipf eclipse (popular chunks have short paths, rescued most) — with
      the extra-hop cost of an eclipsed lookup on the right axis.

Usage (in a venv with matplotlib):  python experiments/plot_b4.py
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CSV = REPO_ROOT / "results" / "B4_eclipse.csv"
FIG = REPO_ROOT / "results" / "fig_B4_eclipse.png"


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
        print(f"missing {CSV} — run experiments/b4_inproc.py first", file=sys.stderr)
        return 1
    rows = load_rows()
    rnd = sorted((r for r in rows if r["block"] == "random"), key=lambda r: _f(r["realized_f_pct"]))
    tgt = [r for r in rows if r["block"].startswith("targeted")]

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    EMU, ROUT, STRUCT, TGT, E2E, HOPS = "#2a78d6", "#8a1c5a", "#c47f16", "#1f8a4c", "#555555", "#b1341f"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    fig, axes = plt.subplots(1, 2, figsize=(11.6, 4.4))
    xs = [_f(r["realized_f_pct"]) for r in rnd]

    # --- panel 1: raw-DHT + e2e success vs f ---
    ax = axes[0]
    if rnd:
        ax.errorbar(xs, [_f(r["raw_dht_success_pct"]) for r in rnd],
                    yerr=[_f(r["raw_dht_success_sd"]) for r in rnd], marker="o", ms=6, lw=1.8,
                    capsize=3, color=EMU, label="raw-DHT success (measured, Zipf)")
        ax.errorbar(xs, [_f(r["e2e_success_pct"]) for r in rnd],
                    yerr=[_f(r["e2e_success_sd"]) for r in rnd], marker="s", ms=5, lw=1.4, ls="--",
                    capsize=3, color=E2E, label="end-to-end success (fallback recovers)")
    for i, t in enumerate(tgt):
        raw = _f(t["target_raw_dht_success_pct"]); e2e = _f(t["target_e2e_success_pct"])
        kind = t["block"].split("_")[1]
        fx = _f(t["realized_f_pct"])
        ax.scatter([fx], [raw], marker="*", s=240, color=TGT, zorder=5,
                   label=f"targeted {kind}: one misrouter (f≈{fx:.0f}%)" if i == 0
                   else f"targeted {kind}")
        ax.annotate(f"{t.get('target','')}: DHT→{raw:.0f}% (e2e {e2e:.0f}%)",
                    (fx, raw), textcoords="offset points",
                    xytext=(14, 18 + 20 * i), fontsize=8, color=TGT,
                    arrowprops=dict(arrowstyle="-", color=TGT, lw=0.6))
    ax.axhline(100, color=GRID, lw=1.0, zorder=0)
    ax.set_xlabel("adversary fraction f (%)")
    ax.set_ylabel("lookup success (%)")
    ax.set_title("Raw-DHT vs end-to-end success (N=32, s=3)")
    ax.set_ylim(-4, 108)
    ax.legend(frameon=False, fontsize=8, loc="center left")

    # --- panel 2: eclipse decomposition + extra-hop cost ---
    ax = axes[1]
    if rnd:
        ax.plot(xs, [_f(r["routing_eclipsed_pct"]) for r in rnd], marker="^", ms=6, lw=1.8,
                color=ROUT, label="routing-eclipsed (wrong owner)")
        ax.plot(xs, [_f(r["structural_eclipsed_pct"]) for r in rnd], marker="o", ms=6, lw=1.8,
                color=STRUCT, label="DHT-denied (replication rescues the gap)")
        ax.plot(xs, [_f(r["eclipse_rate_pct"]) for r in rnd], marker="s", ms=5, lw=1.8,
                color=EMU, label="measured eclipse (Zipf; popular rescued most)")
    ax.set_xlabel("adversary fraction f (%)")
    ax.set_ylabel("eclipsed lookups (%)")
    ax.set_title("Eclipse decomposition + extra-hop cost")
    ax.set_ylim(bottom=-2)
    ax.legend(frameon=False, fontsize=8, loc="upper left")

    ax2 = ax.twinx()
    ax2.plot(xs, [_f(r["extra_hops_delta_vs_f0"]) for r in rnd], marker="D", ms=5, lw=1.4, ls=":",
             color=HOPS, label="extra hops of an eclipsed lookup (Δ vs f=0)")
    ax2.set_ylabel("extra hops (Δ vs honest f=0)", color=HOPS)
    ax2.tick_params(axis="y", colors=HOPS)
    ax2.set_ylim(0, 4)
    ax2.grid(False)
    ax2.legend(frameon=False, fontsize=8, loc="lower right")

    fig.suptitle("B4 — routing / eclipse: replication + fallback blunt RANDOM misroute (raw-DHT ≥89% "
                 "to f=50%, e2e 100%), but ONE misrouter isolates a chosen victim", y=1.02, fontsize=11)
    fig.tight_layout()
    fig.savefig(FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {FIG.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
