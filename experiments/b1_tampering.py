#!/usr/bin/env python3
"""Issue #42 [B1] — Tampering / cache poisoning: aggregate + bound overlay (Phase 7, point (ii)).

Reads the raw snapshots collected by experiments/run_b1.sh and produces the deliverables:

    results/B1_tampering.csv        tidy long table (random sweep + targeted demo)
    results/fig_B1_tampering.png    forged-acceptance vs f, with the majority-vote bound overlaid

Metric (the issue's headline): **% forged answers accepted by clients** = client replies whose A
record is the forged 6.6.6.6 (answer_ip != expected answer_ip) over all SUCCESSFUL replies, from
query_gen.py's --check-answers columns. Overlaid against the majority-vote bound:

  * analytic  — P(Binom(s,f) >= ceil((s+1)/2)) = 3f^2-2f^3 at s=3 (i.i.d. random placement limit);
  * structural — fraction of the 1000 served chunks whose replica set actually holds >= 2 malicious
                 under THIS run's seeded placement (the realized bound; from b1_placement.py).

Honest control = f=0 (expect ~0% forged). Also reports DNS success rate vs f: it stays ~flat
because a forged answer still "succeeds" at the DNS level — the harm is INTEGRITY, not
availability; the attack's effect is the forged-acceptance delta over f=0, not degraded success.

Usage:
    python3 experiments/b1_tampering.py            # table + figure from results/b1/
    python3 experiments/b1_tampering.py --no-plot
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
B1_DIR = RESULTS / "b1"
OUT_CSV = RESULTS / "B1_tampering.csv"
OUT_FIG = RESULTS / "fig_B1_tampering.png"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from experiments.b1_placement import (  # noqa: E402
    analytic_bound, effective_bound, structural_capture_fraction, load_served_domains,
)

# frozen workload (PARAMETERS.md §1)
B1_N = 32
B1_S = 3
B1_QPS = 10
SEED = 20260919


# ---- percentile / stats helpers — identical to experiments/a4_replication.py ----
def _percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * p
    lo = int(math.floor(k))
    hi = min(lo + 1, len(sorted_vals) - 1)
    if lo == hi:
        return sorted_vals[lo]
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def _pcts(latencies: list[float]) -> tuple[float, float, float]:
    s = sorted(latencies)
    return _percentile(s, 0.50), _percentile(s, 0.95), _percentile(s, 0.99)


def _mean_sd(vals: list[float]) -> tuple[float, float]:
    vals = [v for v in vals if not math.isnan(v)]
    if not vals:
        return float("nan"), 0.0
    m = statistics.fmean(vals)
    sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
    return m, sd


def load_b1_client_rows(path: Path) -> list[dict]:
    """Parse a --check-answers client CSV: timestamp,domain,resolver_used,latency_ms,success,
    expected_ip,answer_ip,forged."""
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out.append({
                "domain": r["domain"],
                "latency": float(r["latency_ms"]),
                "success": str(r["success"]).strip().lower() == "true",
                "answer_ip": r.get("answer_ip", ""),
                "forged": str(r.get("forged", "")).strip().lower() == "true",
            })
    return out


def _run_metrics(run_dir: Path) -> dict | None:
    """Per-run: forged-acceptance (query-weighted + distinct), success rate, latency pcts, and the
    structural capture fraction from this run's recorded placement."""
    client = run_dir / "client.csv"
    if not client.exists():
        return None
    rows = load_b1_client_rows(client)
    if not rows:
        return None
    ok = [r for r in rows if r["success"]]                      # NOERROR + has A record
    answered = [r for r in ok if r["answer_ip"]]               # defensive (success ⇒ answer_ip set)
    forged = [r for r in answered if r["forged"]]

    # distinct-domain forged fraction (cache lock-in makes a chunk consistently forged or not).
    by_dom: dict[str, list[bool]] = {}
    for r in answered:
        by_dom.setdefault(r["domain"], []).append(r["forged"])
    dom_forged = sum(1 for v in by_dom.values() if sum(v) > len(v) / 2)
    distinct_pct = 100.0 * dom_forged / len(by_dom) if by_dom else float("nan")

    p50, p95, p99 = _pcts([r["latency"] for r in ok])

    # structural capture from the recorded placement (realized bounds over all 1000 chunks):
    # majority (>=2 of 3, the intended vote bound) and single (>=1, the achieved bound).
    struct_maj = struct_single = float("nan")
    pj = run_dir / "placement.json"
    if pj.exists():
        meta = json.loads(pj.read_text())
        idx = [int(x) for x in str(meta.get("indices", "")).split(",") if x.strip() != ""]
        n, s = meta.get("n", B1_N), meta.get("s", B1_S)
        struct_maj = 100.0 * structural_capture_fraction(idx, n, s)
        struct_single = 100.0 * structural_capture_fraction(idx, n, s, thresh=1)

    return {
        "n_queries": len(rows), "n_ok": len(ok), "n_answered": len(answered),
        "forged_pct": 100.0 * len(forged) / len(answered) if answered else float("nan"),
        "distinct_pct": distinct_pct,
        "success_pct": 100.0 * len(ok) / len(rows),
        "p50": p50, "p95": p95, "p99": p99,
        "structural_maj_pct": struct_maj, "structural_single_pct": struct_single,
    }


def _target_forged_pct(run_dir: Path, target: str) -> float:
    """Targeted block: % of the TARGET domain's successful replies that were forged (~100 expected)."""
    rows = load_b1_client_rows(run_dir / "client.csv")
    ans = [r for r in rows if r["success"] and r["answer_ip"] and r["domain"] == target]
    if not ans:
        return float("nan")
    return 100.0 * sum(1 for r in ans if r["forged"]) / len(ans)


def _agg(dirs: list[Path]) -> dict:
    """Mean±sd of per-run metrics over a point's run dirs."""
    runs = [m for d in dirs if (m := _run_metrics(d)) is not None]
    def col(k):
        return _mean_sd([r[k] for r in runs])
    forged_m, forged_sd = col("forged_pct")
    succ_m, succ_sd = col("success_pct")
    return {
        "runs": len(runs),
        "forged_accepted_pct": forged_m, "forged_accepted_sd": forged_sd,
        "forged_distinct_pct": col("distinct_pct")[0],
        "success_rate_pct": succ_m, "success_sd": succ_sd,
        "p50_ms": col("p50")[0], "p95_ms": col("p95")[0], "p99_ms": col("p99")[0],
        "structural_majority_pct": col("structural_maj_pct")[0],
        "structural_single_pct": col("structural_single_pct")[0],
    }


# ---------------------------------------------------------------------------------------
# Build the rows.
# ---------------------------------------------------------------------------------------
def random_rows() -> list[dict]:
    rdir = B1_DIR / "random"
    rows = []
    if not rdir.is_dir():
        return rows
    for fdir in sorted(rdir.glob("f*"), key=lambda p: int(p.name[1:])):
        f_pct = int(fdir.name[1:])
        run_dirs = sorted(d for d in fdir.glob("run*") if d.is_dir())
        agg = _agg(run_dirs)
        if agg["runs"] == 0:
            continue
        n_mal = round(f_pct / 100 * B1_N)
        realized_f = n_mal / B1_N
        rows.append({
            "block": "random", "f_pct": f_pct, "n_mal": n_mal,
            "realized_f_pct": 100.0 * realized_f,
            "bound_majority_pct": 100.0 * analytic_bound(realized_f, B1_S),
            "bound_single_pct": 100.0 * effective_bound(realized_f, B1_S),
            "target": "", "target_forged_pct": float("nan"),
            "note": "honest control" if f_pct == 0 else "",
            **agg,
        })
    return rows


def targeted_rows() -> list[dict]:
    tdir = B1_DIR / "targeted"
    if not tdir.is_dir():
        return []
    run_dirs = sorted(d for d in tdir.glob("run*") if d.is_dir())
    if not run_dirs:
        return []
    agg = _agg(run_dirs)
    if agg["runs"] == 0:
        return []
    # target domain + per-target forged rate (per run, then averaged)
    targets, tgt_forged, n_mals = [], [], []
    for d in run_dirs:
        pj = d / "placement.json"
        if pj.exists():
            meta = json.loads(pj.read_text())
            tgt = meta.get("target") or ""
            targets.append(tgt)
            n_mals.append(meta.get("n_mal", 0))
            if tgt:
                tgt_forged.append(_target_forged_pct(d, tgt))
    n_mal = round(statistics.fmean(n_mals)) if n_mals else 0
    realized_f = n_mal / B1_N
    return [{
        "block": "targeted", "f_pct": round(100.0 * realized_f), "n_mal": n_mal,
        "realized_f_pct": 100.0 * realized_f,
        "bound_majority_pct": 100.0 * analytic_bound(realized_f, B1_S),
        "bound_single_pct": 100.0 * effective_bound(realized_f, B1_S),
        "target": targets[0] if targets else "",
        "target_forged_pct": _mean_sd(tgt_forged)[0] if tgt_forged else float("nan"),
        "note": "colluding: 2 nodes co-located on one chunk's replica set (crosses the bound)",
        **agg,
    }]


# ---------------------------------------------------------------------------------------
# CSV.
# ---------------------------------------------------------------------------------------
FIELDS = ["block", "f_pct", "n_mal", "realized_f_pct", "runs",
          "forged_accepted_pct", "forged_accepted_sd", "forged_distinct_pct",
          "bound_majority_pct", "bound_single_pct",
          "structural_majority_pct", "structural_single_pct",
          "success_rate_pct", "success_sd", "p50_ms", "p95_ms", "p99_ms",
          "target", "target_forged_pct", "note"]


def _fmt(v) -> str:
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.4f}"
    return str(v)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def write_csv(rows: list[dict]) -> None:
    def key(r):
        return (0 if r["block"] == "random" else 1, r["realized_f_pct"])
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=key):
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# ---------------------------------------------------------------------------------------
# Plot: forged-acceptance vs f with the bound overlaid + success-rate vs f. Style mirrors A4.
# ---------------------------------------------------------------------------------------
def make_plot(rows: list[dict]) -> None:
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

    rnd = sorted([r for r in rows if r["block"] == "random"], key=lambda r: r["realized_f_pct"])
    tgt = [r for r in rows if r["block"] == "targeted"]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    # --- panel 1: forged-acceptance vs f, with BOTH bounds overlaid ---
    ax = axes[0]
    # smooth bound curves: the INTENDED majority bound (3f²−2f³) and the ACHIEVED single-replica
    # bound (1−(1−f)^s) the implementation actually exhibits (abstention + fabrication).
    fs = [i / 200 for i in range(0, 101)]       # 0..0.5
    ax.plot([100 * f for f in fs], [100 * analytic_bound(f, B1_S) for f in fs],
            lw=1.6, color=BOUND, label="intended majority bound 3f²−2f³ (≥2/3 lie)")
    ax.plot([100 * f for f in fs], [100 * effective_bound(f, B1_S) for f in fs],
            lw=1.6, ls="--", color=STRUCT, label="achieved bound 1−(1−f)³ (≥1/3 lie)")
    if rnd:
        ax.errorbar([r["realized_f_pct"] for r in rnd], [r["forged_accepted_pct"] for r in rnd],
                    yerr=[r["forged_accepted_sd"] for r in rnd], marker="o", ms=6, lw=1.8,
                    capsize=3, color=EMU, label="measured (random placement)")
    for t in tgt:        # targeted demo sits above the bound at a low f
        ax.scatter([t["realized_f_pct"]], [t["forged_accepted_pct"]], marker="*", s=180,
                   color=TGT, zorder=5,
                   label=f"targeted (overall, f≈{t['realized_f_pct']:.0f}%)")
        if not math.isnan(t["target_forged_pct"]):
            ax.annotate(f"target chunk\nforged {t['target_forged_pct']:.0f}%",
                        (t["realized_f_pct"], t["forged_accepted_pct"]),
                        textcoords="offset points", xytext=(8, 8), fontsize=8, color=TGT)
    ax.set_xlabel("adversary fraction f (%)")
    ax.set_ylabel("forged answers accepted (%)")
    ax.set_title("Forged-acceptance vs f, with majority-vote bound (N=32, s=3)")
    ax.set_ylim(bottom=-2)
    ax.legend(frameon=False, fontsize=8, loc="upper left")

    # --- panel 2: DNS success rate vs f (flat → integrity harm, not availability) ---
    ax = axes[1]
    if rnd:
        ax.errorbar([r["realized_f_pct"] for r in rnd], [r["success_rate_pct"] for r in rnd],
                    yerr=[r["success_sd"] for r in rnd], marker="o", ms=6, lw=1.8,
                    capsize=3, color=EMU, label="DNS success rate")
    ax.set_xlabel("adversary fraction f (%)")
    ax.set_ylabel("end-to-end success (%)")
    ax.set_title("Success rate vs f (flat → harm is integrity, not availability)")
    ax.set_ylim(0, 105)
    ax.legend(frameon=False, fontsize=9, loc="lower left")

    fig.suptitle("B1 — tampering / cache poisoning: forged-acceptance vs the majority-vote bound",
                 y=1.02, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="B1 tampering/cache-poisoning analysis (issue #42).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    args = ap.parse_args()

    rows = random_rows() + targeted_rows()
    if not rows:
        print(f"no snapshots under {_rel(B1_DIR)} — run experiments/run_b1.sh first", file=sys.stderr)
        return 1

    print("== B1: forged-acceptance vs f (majority bound = intended ≥2/3; single bound = achieved ≥1/3) ==")
    for r in sorted(rows, key=lambda r: (0 if r["block"] == "random" else 1, r["realized_f_pct"])):
        tail = f" target={r['target']} target_forged={r['target_forged_pct']:.1f}%" if r["block"] == "targeted" else ""
        print(f"  [{r['block']:>8} f={r['realized_f_pct']:5.1f}% n_mal={r['n_mal']:>2} runs={r['runs']}] "
              f"forged={r['forged_accepted_pct']:6.2f}%  maj-bound={r['bound_majority_pct']:5.2f}% "
              f"single-bound={r['bound_single_pct']:5.2f}%  struct(≥1)={r['structural_single_pct']:5.2f}% "
              f"success={r['success_rate_pct']:5.1f}%{tail}")

    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
