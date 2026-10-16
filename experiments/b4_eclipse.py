#!/usr/bin/env python3
"""Issue #45 [B4] — Routing / eclipse: OPTIONAL socket cross-check analyzer (Phase 7, point (ii)).

Reads the raw snapshots collected by experiments/run_b4.sh (a socket-testbed anchor) and writes:

    results/B4_eclipse_socket.csv    tidy long table (random anchor + optional targeted demo)
    results/fig_B4_eclipse_socket.png

A SEPARATE file from the PRIMARY results/B4_eclipse.csv (experiments/b4_inproc.py), so a slow/flaky
testbed run never clobbers the in-process ground truth. Metrics mirror the primary and B3:

  * raw-DHT lookup success (HEADLINE) — node 0's queries.csv: dht_hit/(dht_hit+fallback). Eclipse rate
    = its complement (fallback-forced). Misroute poisons routing to the wrong primary, but the
    s-replica read over that primary's successor list often overlaps the true replica set, so the
    chunk is still found — replication rescues routing eclipse (the routing mirror of B3).
  * extra hops — node 0's queries.csv `hops`, split dht_hit vs fallback; the fallback penalty over the
    f=0 honest control is the issue's "extra hops for the eclipsed node".
  * end-to-end success (SECONDARY) + latency — client.csv; e2e stays high (fallback recovers).

Honest control = f=0. Usage:
    python3 experiments/b4_eclipse.py            # table + figure from results/b4/
    python3 experiments/b4_eclipse.py --no-plot
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
B4_DIR = RESULTS / "b4"
OUT_CSV = RESULTS / "B4_eclipse_socket.csv"
OUT_FIG = RESULTS / "fig_B4_eclipse_socket.png"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from experiments.b4_placement import structural_denied_fraction, eclipse_bound, honest_mean_hops  # noqa: E402

B4_N = 32
B4_S = 3
SEED = 20260919


def _percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * p
    lo = int(math.floor(k)); hi = min(lo + 1, len(sorted_vals) - 1)
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
    return m, (statistics.stdev(vals) if len(vals) > 1 else 0.0)


def load_client_rows(path: Path) -> list[dict]:
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out.append({"domain": r["domain"], "latency": float(r["latency_ms"]),
                        "success": str(r["success"]).strip().lower() == "true"})
    return out


def load_node_queries(path: Path) -> list[dict]:
    """node queries.csv: timestamp,domain,hops,outcome,vote_result."""
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out.append({"domain": r["domain"], "hops": float(r["hops"]), "outcome": r["outcome"]})
    return out


def _node0_queries(run_dir: Path) -> list[dict]:
    p = run_dir / "ring" / "0_queries.csv"
    return load_node_queries(p) if p.exists() else []


def _run_metrics(run_dir: Path) -> dict | None:
    client = run_dir / "client.csv"
    if not client.exists():
        return None
    crows = load_client_rows(client)
    if not crows:
        return None
    ok = [r for r in crows if r["success"]]
    p50, p95, p99 = _pcts([r["latency"] for r in ok]) if ok else (float("nan"),) * 3

    q = _node0_queries(run_dir)
    dht = [r["hops"] for r in q if r["outcome"] == "dht_hit"]
    fb = [r["hops"] for r in q if r["outcome"] == "fallback"]
    looked = len(dht) + len(fb)
    raw = 100.0 * len(dht) / looked if looked else float("nan")
    eclipse = 100.0 * len(fb) / looked if looked else float("nan")

    struct = float("nan")
    pj = run_dir / "placement.json"
    if pj.exists():
        meta = json.loads(pj.read_text())
        idx = [int(x) for x in str(meta.get("indices", "")).split(",") if x.strip() != ""]
        n, s = meta.get("n", B4_N), meta.get("s", B4_S)
        struct = 100.0 * structural_denied_fraction(idx, n, SEED, s)

    return {
        "n_queries": len(crows), "n_ok": len(ok),
        "raw_dht_success_pct": raw, "eclipse_rate_pct": eclipse,
        "e2e_success_pct": 100.0 * len(ok) / len(crows),
        "mean_hops_dht": statistics.fmean(dht) if dht else float("nan"),
        "mean_hops_eclipsed": statistics.fmean(fb) if fb else float("nan"),
        "p50": p50, "p95": p95, "p99": p99,
        "structural_eclipsed_pct": struct,
    }


def _target_metrics(run_dir: Path, victim_idx) -> tuple[float, float]:
    """Targeted: (victim-range raw-DHT success %, e2e %). The victim's chunks are those routed to the
    victim; we approximate by node 0's queries whose outcome distribution reflects the denial. Since
    the socket run enters only node 0 over all domains, we report the overall raw-DHT/e2e of this run
    (the victim block corrupts one on-path hop → its range's chunks fall back)."""
    q = _node0_queries(run_dir)
    dht = sum(1 for r in q if r["outcome"] == "dht_hit")
    fb = sum(1 for r in q if r["outcome"] == "fallback")
    raw = 100.0 * dht / (dht + fb) if (dht + fb) else float("nan")
    crows = load_client_rows(run_dir / "client.csv")
    e2e = 100.0 * sum(1 for r in crows if r["success"]) / len(crows) if crows else float("nan")
    return raw, e2e


def _agg(dirs: list[Path]) -> dict:
    runs = [m for d in dirs if (m := _run_metrics(d)) is not None]

    def col(k):
        return _mean_sd([r[k] for r in runs])
    raw_m, raw_sd = col("raw_dht_success_pct")
    ecl_m, ecl_sd = col("eclipse_rate_pct")
    e2e_m, e2e_sd = col("e2e_success_pct")
    return {
        "runs": len(runs),
        "raw_dht_success_pct": raw_m, "raw_dht_success_sd": raw_sd,
        "eclipse_rate_pct": ecl_m, "eclipse_rate_sd": ecl_sd,
        "e2e_success_pct": e2e_m, "e2e_success_sd": e2e_sd,
        "mean_hops_dht": col("mean_hops_dht")[0], "mean_hops_eclipsed": col("mean_hops_eclipsed")[0],
        "p50_ms": col("p50")[0], "p95_ms": col("p95")[0], "p99_ms": col("p99")[0],
        "structural_eclipsed_pct": col("structural_eclipsed_pct")[0],
    }


def random_rows() -> list[dict]:
    rdir = B4_DIR / "random"
    rows = []
    if not rdir.is_dir():
        return rows
    L = honest_mean_hops(B4_N, B4_S)
    for fdir in sorted(rdir.glob("f*"), key=lambda p: int(p.name[1:])):
        f_pct = int(fdir.name[1:])
        run_dirs = sorted(d for d in fdir.glob("run*") if d.is_dir())
        agg = _agg(run_dirs)
        if agg["runs"] == 0:
            continue
        n_mal = round(f_pct / 100 * B4_N)
        realized_f = n_mal / B4_N
        rows.append({
            "source": "emulation", "block": "random", "f_pct": f_pct, "n_mal": n_mal,
            "realized_f_pct": 100.0 * realized_f,
            "bound_eclipsed_pct": 100.0 * eclipse_bound(realized_f, L),
            "target": "", "target_raw_dht_success_pct": float("nan"),
            "target_e2e_success_pct": float("nan"),
            "note": "honest control" if f_pct == 0 else "",
            **agg,
        })
    base = next((r["mean_hops_dht"] for r in rows if r["f_pct"] == 0), float("nan"))
    bp95 = next((r["p95_ms"] for r in rows if r["f_pct"] == 0), float("nan"))
    for r in rows:
        r["extra_hops_delta_vs_f0"] = (r["mean_hops_eclipsed"] - base) if not math.isnan(base) else float("nan")
        r["added_p95_ms"] = (r["p95_ms"] - bp95) if not math.isnan(bp95) else float("nan")
    return rows


def targeted_rows() -> list[dict]:
    tdir = B4_DIR / "targeted"
    if not tdir.is_dir():
        return []
    run_dirs = sorted(d for d in tdir.glob("run*") if d.is_dir())
    agg = _agg(run_dirs)
    if agg["runs"] == 0:
        return []
    raws, e2es, vics = [], [], []
    for d in run_dirs:
        pj = d / "placement.json"
        vic = json.loads(pj.read_text()).get("victim_idx") if pj.exists() else None
        raw, e2e = _target_metrics(d, vic)
        raws.append(raw); e2es.append(e2e); vics.append(vic)
    return [{
        "source": "emulation", "block": "targeted_node", "f_pct": round(100.0 / B4_N, 4), "n_mal": 1,
        "realized_f_pct": 100.0 / B4_N,
        "bound_eclipsed_pct": float("nan"), "extra_hops_delta_vs_f0": float("nan"),
        "added_p95_ms": float("nan"),
        "target": f"node#{vics[0]}" if vics and vics[0] is not None else "",
        "target_raw_dht_success_pct": _mean_sd(raws)[0],
        "target_e2e_success_pct": _mean_sd(e2es)[0],
        "note": "one misrouter eclipses a victim node's range (DHT denied, fallback recovers)",
        **agg,
    }]


FIELDS = ["source", "block", "f_pct", "n_mal", "realized_f_pct", "runs",
          "raw_dht_success_pct", "raw_dht_success_sd",
          "eclipse_rate_pct", "eclipse_rate_sd",
          "e2e_success_pct", "e2e_success_sd",
          "bound_eclipsed_pct", "structural_eclipsed_pct",
          "mean_hops_dht", "mean_hops_eclipsed", "extra_hops_delta_vs_f0",
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


def make_plot(rows: list[dict]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    EMU, STRUCT, TGT, E2E = "#2a78d6", "#c47f16", "#1f8a4c", "#555555"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    rnd = sorted([r for r in rows if r["block"] == "random"], key=lambda r: r["realized_f_pct"])
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    ax = axes[0]
    if rnd:
        ax.errorbar([r["realized_f_pct"] for r in rnd], [r["raw_dht_success_pct"] for r in rnd],
                    yerr=[r["raw_dht_success_sd"] for r in rnd], marker="o", ms=6, lw=1.8,
                    capsize=3, color=EMU, label="raw-DHT success (measured)")
        ax.errorbar([r["realized_f_pct"] for r in rnd], [r["e2e_success_pct"] for r in rnd],
                    yerr=[r["e2e_success_sd"] for r in rnd], marker="s", ms=5, lw=1.4, ls="--",
                    capsize=3, color=E2E, label="end-to-end success (fallback recovers)")
    ax.set_xlabel("adversary fraction f (%)"); ax.set_ylabel("lookup success (%)")
    ax.set_title("Raw-DHT vs end-to-end success (socket, N=32, s=3)")
    ax.set_ylim(-2, 105); ax.legend(frameon=False, fontsize=8, loc="lower left")

    ax = axes[1]
    if rnd:
        ax.errorbar([r["realized_f_pct"] for r in rnd], [r["p95_ms"] for r in rnd],
                    marker="o", ms=6, lw=1.8, color=STRUCT, label="p95 latency")
        ax.plot([r["realized_f_pct"] for r in rnd], [r["p50_ms"] for r in rnd],
                marker="s", ms=5, lw=1.4, ls="--", color=EMU, label="p50 latency")
    ax.set_xlabel("adversary fraction f (%)"); ax.set_ylabel("latency (ms)")
    ax.set_title("Latency vs f (socket anchor)")
    ax.set_ylim(bottom=0); ax.legend(frameon=False, fontsize=9, loc="upper left")

    fig.suptitle("B4 — routing/eclipse (socket cross-check): raw-DHT falls with f, e2e stays high",
                 y=1.02, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


def main() -> int:
    ap = argparse.ArgumentParser(description="B4 routing/eclipse socket cross-check (issue #45).")
    ap.add_argument("--no-plot", action="store_true")
    args = ap.parse_args()

    rows = random_rows() + targeted_rows()
    if not rows:
        print(f"no snapshots under {_rel(B4_DIR)} — run experiments/run_b4.sh first", file=sys.stderr)
        return 1
    for r in sorted(rows, key=lambda r: (0 if r["block"] == "random" else 1, r["realized_f_pct"])):
        print(f"  [{r['block']:>14} f={r['realized_f_pct']:5.1f}% n_mal={r['n_mal']:>2} runs={r['runs']}] "
              f"raw-DHT={r['raw_dht_success_pct']:6.2f}% eclipse={r['eclipse_rate_pct']:6.2f}% "
              f"e2e={r['e2e_success_pct']:5.1f}% p95={r['p95_ms']:6.0f}ms")
    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
