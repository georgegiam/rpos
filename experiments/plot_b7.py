#!/usr/bin/env python3
"""Issue #48 [B7] — DoS figure (Phase 7). Standalone: matplotlib + stdlib only, NO node/dnspython
imports, so it runs in a minimal plotting env. Reads results/B7_dos.csv (written by b7_dos.py).

Four panels:
  (1) FLOOD — honest-probe success vs offered intensity, attack vs control (the honest-control delta);
  (2) FLOOD — honest-probe p95 latency vs intensity, attack vs control;
  (3) FLOOD — ring health (% correct immediate successors) vs intensity, attack vs control
              (the chord.py fragility quantified — it falls in BOTH arms if the hit is load-driven);
  (4) BLACKHOLE — systemic honest success vs f (drop nodes), with raw-DHT where available.

Prefers source=socket (the primary Docker run); falls back to source=inproc (the mechanism
complement) when the socket run has not been collected yet. Style mirrors plot_b3/plot_b4.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt   # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
CSV = REPO_ROOT / "results" / "B7_dos.csv"
FIG = REPO_ROOT / "results" / "fig_B7_dos.png"

A_COL = "#c0392b"      # attack
C_COL = "#2e86de"      # control / honest baseline
R_COL = "#27ae60"      # raw-DHT


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return float("nan")


def load() -> list[dict]:
    if not CSV.exists():
        print(f"[plot_b7] missing {CSV}; run experiments/b7_dos.py first")
        sys.exit(1)
    with open(CSV, newline="") as f:
        return list(csv.DictReader(f))


def flood_series(rows, source, arm, ycol):
    pts = [(_f(r["intensity"]), _f(r[ycol])) for r in rows
           if r["block"] == "flood" and r["source"] == source and r["arm"] == arm
           and r["intensity"] != ""]
    pts = sorted((x, y) for x, y in pts if x == x and y == y)
    return [x for x, _ in pts], [y for _, y in pts]


def main() -> int:
    rows = load()
    src = "socket" if any(r["source"] == "socket" and r["block"] == "flood" for r in rows) else "inproc"
    xlabel = "offered flood rate R (RPC/s)" if src == "socket" else "flood concurrency C (in-flight RPCs)"

    fig, axes = plt.subplots(2, 2, figsize=(13, 9))
    fig.suptitle(f"B7 — DoS flood: effect on honest clients, attack vs honest-control "
                 f"(N=32, s=3, source={src})", fontsize=13, fontweight="bold")

    # (1) success vs intensity
    ax = axes[0][0]
    for arm, col in (("attack", A_COL), ("control", C_COL)):
        x, y = flood_series(rows, src, arm, "honest_success_pct")
        if x:
            ax.plot(x, y, "o-", color=col, label=arm)
    ax.set_title("(1) honest-probe success vs flood intensity")
    ax.set_xlabel(xlabel); ax.set_ylabel("success (%)"); ax.set_ylim(0, 105)
    ax.grid(True, alpha=0.3); ax.legend()

    # (2) p95 vs intensity
    ax = axes[0][1]
    for arm, col in (("attack", A_COL), ("control", C_COL)):
        x, y = flood_series(rows, src, arm, "p95_ms")
        if x:
            ax.plot(x, y, "o-", color=col, label=arm)
    ax.set_title("(2) honest-probe p95 latency vs flood intensity")
    ax.set_xlabel(xlabel); ax.set_ylabel("p95 latency (ms)")
    ax.grid(True, alpha=0.3); ax.legend()

    # (3) ring health vs intensity
    ax = axes[1][0]
    for arm, col in (("attack", A_COL), ("control", C_COL)):
        x, y = flood_series(rows, src, arm, "ring_correct_succ_pct")
        if x:
            ax.plot(x, y, "o-", color=col, label=arm)
    ax.set_title("(3) ring health (% correct successors) vs flood intensity\n"
                 "chord.py fragility — falls in BOTH arms if load-driven")
    ax.set_xlabel(xlabel); ax.set_ylabel("correct immediate successors (%)")
    ax.set_ylim(0, 105); ax.grid(True, alpha=0.3); ax.legend()

    # (4) blackhole success vs f
    ax = axes[1][1]
    bh = sorted([r for r in rows if r["block"] == "blackhole"], key=lambda r: _f(r["f_pct"]))
    if bh:
        fx = [_f(r["f_pct"]) for r in bh]
        ax.plot(fx, [_f(r["honest_success_pct"]) for r in bh], "o-", color=C_COL,
                label="e2e success")
        raw = [(_f(r["f_pct"]), _f(r["note"].split("raw-DHT")[1].rstrip("% ").strip()))
               for r in bh if "raw-DHT" in r.get("note", "")]
        raw = [(x, y) for x, y in raw if y == y]
        if raw:
            ax.plot([x for x, _ in raw], [y for _, y in raw], "s--", color=R_COL, label="raw-DHT")
        ax.set_ylim(0, 105); ax.legend()
    else:
        ax.text(0.5, 0.5, "blackhole block: run run_b7.sh (socket)\nto collect",
                ha="center", va="center", transform=ax.transAxes, color="gray")
    ax.set_title("(4) blackhole (drop nodes): systemic honest success vs f")
    ax.set_xlabel("adversary fraction f (%)"); ax.set_ylabel("success (%)")
    ax.grid(True, alpha=0.3)

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    FIG.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG, dpi=130)
    print(f"[plot_b7] wrote {FIG.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
