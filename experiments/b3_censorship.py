#!/usr/bin/env python3
"""Issue #44 [B3] — Censorship: aggregate + bound overlay (Phase 7, examiner point (ii)).

Reads the raw snapshots collected by experiments/run_b3.sh and produces the deliverables:

    results/B3_censorship.csv        tidy long table (random sweep + targeted demo)
    results/fig_B3_censorship.png    raw-DHT success + latency vs f, with the censorship bound

Metrics (the issue's "blocked-domain resolution success rate + added latency"), split A6-style
because the DNS-hierarchy fallback masks denial at the DNS level:

  * raw-DHT lookup success (HEADLINE) — from the HONEST entry node 0's queries.csv:
    dht_hit / (dht_hit + fallback). This exposes the censorship the fallback otherwise hides. A
    ``drop`` node answers no storage RPC, so a chunk's DHT read is DENIED only when ALL s replicas
    drop (one honest replica rescues the majority vote) — the expected floor is 1 − f^s. Overlaid:
      - analytic resolvable 1 − f^s (i.i.d. random-placement limit);
      - structural resolvable 1 − (realized fully-censored fraction over the 1000 served chunks),
        from b3_placement.py — the realized bound this run should match.
  * end-to-end success (SECONDARY) — from client.csv's success column; expected to stay high because
    the fallback re-fetches whatever the DHT denies → the harm is LATENCY, not availability.
  * added latency — client.csv p50/p95/p99, and the p95 DELTA over the f=0 control (the issue's
    "added latency"): accumulated RPC timeouts on dropped replicas push the tail up.

Honest control = f=0 (expect raw-DHT success ~ the no-attack level, no added latency). The targeted
block drops ALL s replicas of one popular chunk → its raw-DHT success → 0, yet it still resolves
end-to-end via fallback (added latency) — the worst-case demo that full capture is latency, not denial.

Usage:
    python3 experiments/b3_censorship.py            # table + figure from results/b3/
    python3 experiments/b3_censorship.py --no-plot
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
B3_DIR = RESULTS / "b3"
# The in-process ring (experiments/b3_inproc.py) owns the primary B3_censorship.csv. This socket
# cross-check writes a SEPARATE file so a (slow, flaky) testbed run never clobbers the primary.
OUT_CSV = RESULTS / "B3_censorship_socket.csv"
OUT_FIG = RESULTS / "fig_B3_censorship_socket.png"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from experiments.b3_placement import (  # noqa: E402
    censor_bound, structural_censored_fraction,
)

# frozen workload (PARAMETERS.md §1)
B3_N = 32
B3_S = 3
B3_QPS = 10
SEED = 20260919


# ---- percentile / stats helpers — identical to experiments/b1_tampering.py ----
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


# ---- CSV loaders ----
def load_client_rows(path: Path) -> list[dict]:
    """Parse a plain client CSV: timestamp,domain,resolver_used,latency_ms,success (B3 has no
    --check-answers forgery columns)."""
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out.append({
                "domain": r["domain"],
                "latency": float(r["latency_ms"]),
                "success": str(r["success"]).strip().lower() == "true",
            })
    return out


def load_node_queries(path: Path) -> list[dict]:
    """Parse a node's queries.csv: timestamp,domain,hops,outcome,vote_result. outcome is one of
    cache_hit / dht_hit / fallback — the raw-DHT outcome signal."""
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out.append({"domain": r["domain"], "outcome": r["outcome"]})
    return out


def _node0_queries(run_dir: Path) -> list[dict]:
    """Node 0 (honest entry) is where all --ring-nodes 1 queries land; its log is the raw-DHT view."""
    p = run_dir / "ring" / "0_queries.csv"
    return load_node_queries(p) if p.exists() else []


# ---- per-run metrics ----
def _raw_dht_success(outcomes: list[str]) -> tuple[float, float, float, float]:
    """(raw_dht_success_pct, cache_pct, dht_pct, fallback_pct) over a node's outcome log.

    raw-DHT success = dht_hit / (dht_hit + fallback): of the lookups that actually reached the DHT
    (cache hits excluded, A6's definition), the fraction served by the DHT rather than forced to
    fall back. Censorship pushes dht_hit → fallback, so this falls as f grows.
    """
    n = len(outcomes)
    if n == 0:
        return float("nan"), float("nan"), float("nan"), float("nan")
    cache = sum(1 for o in outcomes if o == "cache_hit")
    dht = sum(1 for o in outcomes if o == "dht_hit")
    fb = sum(1 for o in outcomes if o == "fallback")
    looked_up = dht + fb
    raw = 100.0 * dht / looked_up if looked_up else float("nan")
    return raw, 100.0 * cache / n, 100.0 * dht / n, 100.0 * fb / n


def _run_metrics(run_dir: Path) -> dict | None:
    """Per-run: raw-DHT success + outcome mix (node 0), e2e success + latency pcts (client), and the
    structural fully-censored fraction from this run's recorded placement."""
    client = run_dir / "client.csv"
    if not client.exists():
        return None
    crows = load_client_rows(client)
    if not crows:
        return None
    ok = [r for r in crows if r["success"]]
    p50, p95, p99 = _pcts([r["latency"] for r in ok]) if ok else (float("nan"),) * 3

    outcomes = [q["outcome"] for q in _node0_queries(run_dir)]
    raw, cache_pct, dht_pct, fb_pct = _raw_dht_success(outcomes)

    # structural fully-censored fraction (all s replicas malicious) from the recorded placement.
    struct = float("nan")
    pj = run_dir / "placement.json"
    if pj.exists():
        meta = json.loads(pj.read_text())
        idx = [int(x) for x in str(meta.get("indices", "")).split(",") if x.strip() != ""]
        n, s = meta.get("n", B3_N), meta.get("s", B3_S)
        struct = 100.0 * structural_censored_fraction(idx, n, s)

    return {
        "n_queries": len(crows), "n_ok": len(ok),
        "raw_dht_success_pct": raw,
        "cache_pct": cache_pct, "dht_pct": dht_pct, "fallback_pct": fb_pct,
        "e2e_success_pct": 100.0 * len(ok) / len(crows),
        "p50": p50, "p95": p95, "p99": p99,
        "structural_censored_pct": struct,
    }


def _target_metrics(run_dir: Path, target: str) -> tuple[float, float]:
    """Targeted block: (target raw-DHT success %, target end-to-end success %) for the one domain
    whose whole replica set drops. Expect raw-DHT → 0 (always falls back) but e2e → high (fallback)."""
    outs = [q["outcome"] for q in _node0_queries(run_dir) if q["domain"] == target]
    raw, _, _, _ = _raw_dht_success(outs)
    crows = [r for r in load_client_rows(run_dir / "client.csv") if r["domain"] == target]
    e2e = 100.0 * sum(1 for r in crows if r["success"]) / len(crows) if crows else float("nan")
    return raw, e2e


def _agg(dirs: list[Path]) -> dict:
    """Mean±sd of per-run metrics over a point's run dirs."""
    runs = [m for d in dirs if (m := _run_metrics(d)) is not None]

    def col(k):
        return _mean_sd([r[k] for r in runs])
    raw_m, raw_sd = col("raw_dht_success_pct")
    e2e_m, e2e_sd = col("e2e_success_pct")
    return {
        "runs": len(runs),
        "raw_dht_success_pct": raw_m, "raw_dht_success_sd": raw_sd,
        "e2e_success_pct": e2e_m, "e2e_success_sd": e2e_sd,
        "cache_pct": col("cache_pct")[0], "dht_pct": col("dht_pct")[0],
        "fallback_pct": col("fallback_pct")[0],
        "p50_ms": col("p50")[0], "p95_ms": col("p95")[0], "p99_ms": col("p99")[0],
        "structural_censored_pct": col("structural_censored_pct")[0],
    }


# ---- build rows ----
def random_rows() -> list[dict]:
    rdir = B3_DIR / "random"
    rows = []
    if not rdir.is_dir():
        return rows
    for fdir in sorted(rdir.glob("f*"), key=lambda p: int(p.name[1:])):
        f_pct = int(fdir.name[1:])
        run_dirs = sorted(d for d in fdir.glob("run*") if d.is_dir())
        agg = _agg(run_dirs)
        if agg["runs"] == 0:
            continue
        n_mal = round(f_pct / 100 * B3_N)
        realized_f = n_mal / B3_N
        rows.append({
            "source": "emulation", "block": "random", "f_pct": f_pct, "n_mal": n_mal,
            "realized_f_pct": 100.0 * realized_f,
            "bound_censored_pct": 100.0 * censor_bound(realized_f, B3_S),
            "target": "", "target_raw_dht_success_pct": float("nan"),
            "target_e2e_success_pct": float("nan"),
            "note": "honest control" if f_pct == 0 else "",
            **agg,
        })
    # added_p95_ms = p95 delta over the f=0 honest control (the issue's "added latency").
    base = next((r["p95_ms"] for r in rows if r["f_pct"] == 0), float("nan"))
    for r in rows:
        r["added_p95_ms"] = (r["p95_ms"] - base) if not math.isnan(base) else float("nan")
    return rows


def targeted_rows() -> list[dict]:
    tdir = B3_DIR / "targeted"
    if not tdir.is_dir():
        return []
    run_dirs = sorted(d for d in tdir.glob("run*") if d.is_dir())
    agg = _agg(run_dirs)
    if agg["runs"] == 0:
        return []
    targets, tgt_raw, tgt_e2e, n_mals = [], [], [], []
    for d in run_dirs:
        pj = d / "placement.json"
        if pj.exists():
            meta = json.loads(pj.read_text())
            tgt = meta.get("target") or ""
            targets.append(tgt)
            n_mals.append(meta.get("n_mal", 0))
            if tgt:
                raw, e2e = _target_metrics(d, tgt)
                tgt_raw.append(raw)
                tgt_e2e.append(e2e)
    n_mal = round(statistics.fmean(n_mals)) if n_mals else 0
    realized_f = n_mal / B3_N
    return [{
        "source": "emulation", "block": "targeted", "f_pct": round(100.0 * realized_f), "n_mal": n_mal,
        "realized_f_pct": 100.0 * realized_f,
        "bound_censored_pct": 100.0 * censor_bound(realized_f, B3_S),
        "added_p95_ms": float("nan"),
        "target": targets[0] if targets else "",
        "target_raw_dht_success_pct": _mean_sd(tgt_raw)[0] if tgt_raw else float("nan"),
        "target_e2e_success_pct": _mean_sd(tgt_e2e)[0] if tgt_e2e else float("nan"),
        "note": "full-replica capture: all s replicas of one popular chunk dropped (DHT denied, "
                "fallback recovers)",
        **agg,
    }]


# ---- CSV ----
FIELDS = ["source", "block", "f_pct", "n_mal", "realized_f_pct", "runs",
          "raw_dht_success_pct", "raw_dht_success_sd",
          "e2e_success_pct", "e2e_success_sd",
          "bound_censored_pct", "structural_censored_pct",
          "cache_pct", "dht_pct", "fallback_pct",
          "p50_ms", "p95_ms", "p99_ms", "added_p95_ms",
          "target", "target_raw_dht_success_pct", "target_e2e_success_pct", "note"]


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


# ---- plot: raw-DHT success + added latency vs f, with the censorship bound. Style mirrors B1. ----
def make_plot(rows: list[dict]) -> None:
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

    rnd = sorted([r for r in rows if r["block"] == "random"], key=lambda r: r["realized_f_pct"])
    tgt = [r for r in rows if r["block"] == "targeted"]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    # --- panel 1: raw-DHT success + end-to-end success vs f, with the resolvable bound ---
    ax = axes[0]
    fs = [i / 200 for i in range(0, 101)]       # 0..0.5
    ax.plot([100 * f for f in fs], [100 * (1 - censor_bound(f, B3_S)) for f in fs],
            lw=1.6, color=BOUND, label="resolvable bound 1−f³ (all s replicas must drop)")
    if rnd:
        ax.errorbar([r["realized_f_pct"] for r in rnd], [r["raw_dht_success_pct"] for r in rnd],
                    yerr=[r["raw_dht_success_sd"] for r in rnd], marker="o", ms=6, lw=1.8,
                    capsize=3, color=EMU, label="raw-DHT success (measured)")
        ax.errorbar([r["realized_f_pct"] for r in rnd], [r["e2e_success_pct"] for r in rnd],
                    yerr=[r["e2e_success_sd"] for r in rnd], marker="s", ms=5, lw=1.4, ls="--",
                    capsize=3, color=E2E, label="end-to-end success (fallback recovers)")
    for t in tgt:
        if not math.isnan(t["target_raw_dht_success_pct"]):
            ax.scatter([t["realized_f_pct"]], [t["target_raw_dht_success_pct"]], marker="*", s=200,
                       color=TGT, zorder=5,
                       label=f"targeted: target raw-DHT (f≈{t['realized_f_pct']:.0f}%)")
            ax.annotate(f"target chunk\nDHT denied → {t['target_raw_dht_success_pct']:.0f}%\n"
                        f"(e2e {t['target_e2e_success_pct']:.0f}% via fallback)",
                        (t["realized_f_pct"], t["target_raw_dht_success_pct"]),
                        textcoords="offset points", xytext=(10, 6), fontsize=8, color=TGT)
    ax.set_xlabel("adversary fraction f (%)")
    ax.set_ylabel("lookup success (%)")
    ax.set_title("Raw-DHT vs end-to-end success under drop-censorship (N=32, s=3)")
    ax.set_ylim(-2, 105)
    ax.legend(frameon=False, fontsize=8, loc="lower left")

    # --- panel 2: added tail latency vs f (the cost the attack actually imposes) ---
    ax = axes[1]
    if rnd:
        ax.errorbar([r["realized_f_pct"] for r in rnd], [r["p95_ms"] for r in rnd],
                    marker="o", ms=6, lw=1.8, color=STRUCT, label="p95 latency")
        ax.plot([r["realized_f_pct"] for r in rnd], [r["p50_ms"] for r in rnd],
                marker="s", ms=5, lw=1.4, ls="--", color=EMU, label="p50 latency")
    ax.set_xlabel("adversary fraction f (%)")
    ax.set_ylabel("latency (ms)")
    ax.set_title("Added latency vs f (the censorship cost: fallback, not denial)")
    ax.set_ylim(bottom=0)
    ax.legend(frameon=False, fontsize=9, loc="upper left")

    fig.suptitle("B3 — censorship: replication + fallback turn denial into added latency",
                 y=1.02, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="B3 censorship analysis (issue #44).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    args = ap.parse_args()

    rows = random_rows() + targeted_rows()
    if not rows:
        print(f"no snapshots under {_rel(B3_DIR)} — run experiments/run_b3.sh first", file=sys.stderr)
        return 1

    print("== B3: raw-DHT success vs f (resolvable bound = 1 − f^s; e2e stays high via fallback) ==")
    for r in sorted(rows, key=lambda r: (0 if r["block"] == "random" else 1, r["realized_f_pct"])):
        if r["block"] == "targeted":
            tail = (f" target={r['target']} raw-DHT={r['target_raw_dht_success_pct']:.1f}% "
                    f"e2e={r['target_e2e_success_pct']:.1f}%")
        else:
            tail = f" added-p95={r['added_p95_ms']:+.0f}ms"
        print(f"  [{r['block']:>8} f={r['realized_f_pct']:5.1f}% n_mal={r['n_mal']:>2} runs={r['runs']}] "
              f"raw-DHT={r['raw_dht_success_pct']:6.2f}%  resolvable-bound={100 - r['bound_censored_pct']:6.2f}% "
              f"struct-censored={r['structural_censored_pct']:5.2f}%  e2e={r['e2e_success_pct']:5.1f}% "
              f"p95={r['p95_ms']:6.0f}ms{tail}")

    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
