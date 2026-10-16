#!/usr/bin/env python3
"""Issue #48 [B7] — DoS: aggregate the socket snapshots + merge the in-process complement.

Produces the single deliverable the issue names, results/B7_dos.csv, with a `source` column
(socket = the primary Docker testbed run from run_b7.sh; inproc = the fast mechanism complement
from b7_inproc.py). It also writes the figure via experiments/plot_b7.py (unless --no-plot).

The metric is the issue's "effect on honest clients' success + latency", with the MANDATORY
honest-control delta:
  * FLOOD block  — per offered intensity R, the honest probe's success + p50/p95/p99 (client.csv)
                   for arm=attack (junk flooder) vs arm=control (matched legitimate load). The
                   protocol-attributable DoS = control_success − attack_success at matched R; ring
                   health (ringhealth.json) is reported beside it as the fragility quantifier.
  * BLACKHOLE    — per f, systemic honest success (client e2e) + latency + raw-DHT (node 0's log).

If the socket snapshots are absent (no Docker run yet), the merged CSV is still produced from the
in-process rows alone — the graceful scope-cut path (B7 is CLAUDE.md's first-to-cut attack).

Usage:
    python3 experiments/b7_dos.py              # merge + table + figure
    python3 experiments/b7_dos.py --no-plot
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
B7_DIR = RESULTS / "b7"
INPROC_CSV = B7_DIR / "B7_inproc.csv"
OUT_CSV = RESULTS / "B7_dos.csv"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from experiments.b3_censorship import (  # noqa: E402 (shared, host-safe helpers)
    _mean_sd, _pcts, load_client_rows, load_node_queries, _raw_dht_success,
)

N = 32
S = 3
SEED = 20260919

FIELDS = ["source", "block", "axis", "intensity", "f_pct", "n_mal", "realized_f_pct", "runs",
          "arm", "honest_success_pct", "honest_success_sd", "p50_ms", "p95_ms", "p99_ms",
          "offered_rpc_per_s", "measured_rpc_per_s", "ring_correct_succ_pct", "ring_orphans",
          "protocol_delta_pct", "note"]


def _fmt(v) -> str:
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.4f}"
    return str(v)


def _read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _run_dirs(parent: Path) -> list[Path]:
    return sorted([d for d in parent.glob("run*") if d.is_dir()]) if parent.exists() else []


# -------------------------------------------------------------------------------------------------
# socket flood block
# -------------------------------------------------------------------------------------------------
def _flood_arm_rows(arm: str) -> dict[int, dict]:
    """One aggregated point per intensity R for the given arm. Returns {R: metrics}."""
    base = B7_DIR / "flood" / arm
    out: dict[int, dict] = {}
    if not base.exists():
        return out
    for idir in sorted(base.glob("i*")):
        try:
            R = int(idir.name[1:])
        except ValueError:
            continue
        succ, p50s, p95s, p99s, hc, orph, mrate = [], [], [], [], [], [], []
        runs = 0
        for rd in _run_dirs(idir):
            cli = rd / "client.csv"
            if not cli.exists():
                continue
            rows = load_client_rows(cli)
            if not rows:
                continue
            runs += 1
            succ.append(100.0 * sum(1 for x in rows if x["success"]) / len(rows))
            a, b, c = _pcts([x["latency"] for x in rows])
            p50s.append(a); p95s.append(b); p99s.append(c)
            health = _read_json(rd / "ringhealth.json")
            if health:
                hc.append(float(health.get("correct_succ_pct", float("nan"))))
                orph.append(float(health.get("orphans", float("nan"))))
            fj = _read_json(rd / "flood.json")
            if fj:
                mrate.append(float(fj.get("achieved_rate", float("nan"))))
        if runs == 0:
            continue
        sm, ssd = _mean_sd(succ)
        out[R] = {
            "runs": runs, "success": sm, "success_sd": ssd,
            "p50": _mean_sd(p50s)[0], "p95": _mean_sd(p95s)[0], "p99": _mean_sd(p99s)[0],
            "hc": _mean_sd(hc)[0] if hc else float("nan"),
            "orph": _mean_sd(orph)[0] if orph else float("nan"),
            "measured_rate": _mean_sd(mrate)[0] if mrate else float("nan"),
        }
    return out


def socket_flood_rows() -> list[dict]:
    attack = _flood_arm_rows("attack")
    control = _flood_arm_rows("control")
    rows: list[dict] = []
    for R in sorted(set(attack) | set(control)):
        a = attack.get(R)
        c = control.get(R)
        delta = (c["success"] - a["success"]) if (a and c) else float("nan")
        for arm, m, rate in (("attack", a, a["measured_rate"] if a else float("nan")),
                             ("control", c, float("nan"))):
            if not m:
                continue
            rows.append({
                "source": "socket", "block": "flood", "axis": "offered_rpc_per_s",
                "intensity": R, "f_pct": "", "n_mal": "", "realized_f_pct": "",
                "runs": m["runs"], "arm": arm,
                "honest_success_pct": m["success"], "honest_success_sd": m["success_sd"],
                "p50_ms": m["p50"], "p95_ms": m["p95"], "p99_ms": m["p99"],
                "offered_rpc_per_s": R,
                "measured_rpc_per_s": rate if arm == "attack" else R,
                "ring_correct_succ_pct": m["hc"], "ring_orphans": m["orph"],
                "protocol_delta_pct": delta if arm == "attack" else float("nan"),
                "note": ("honest control (R=0)" if R == 0 else
                         ("matched-volume honest load" if arm == "control" else "")),
            })
    return rows


# -------------------------------------------------------------------------------------------------
# socket blackhole block
# -------------------------------------------------------------------------------------------------
def socket_blackhole_rows() -> list[dict]:
    base = B7_DIR / "blackhole"
    rows: list[dict] = []
    if not base.exists():
        return rows
    f0_success = float("nan")
    agg: list[tuple[int, dict]] = []
    for fdir in sorted(base.glob("f*"), key=lambda d: int(d.name[1:])):
        f_pct = int(fdir.name[1:])
        n_mal = round(f_pct / 100 * N)
        e2e, raws, p50s, p95s, p99s, hc, orph = [], [], [], [], [], [], []
        runs = 0
        for rd in _run_dirs(fdir):
            cli = rd / "client.csv"
            if not cli.exists():
                continue
            crows = load_client_rows(cli)
            if not crows:
                continue
            runs += 1
            e2e.append(100.0 * sum(1 for x in crows if x["success"]) / len(crows))
            a, b, c = _pcts([x["latency"] for x in crows])
            p50s.append(a); p95s.append(b); p99s.append(c)
            q0 = rd / "ring" / "0_queries.csv"
            if q0.exists():
                raw = _raw_dht_success([x["outcome"] for x in load_node_queries(q0)])[0]
                raws.append(raw)
            health = _read_json(rd / "ringhealth.json")
            if health:
                hc.append(float(health.get("correct_succ_pct", float("nan"))))
                orph.append(float(health.get("orphans", float("nan"))))
        if runs == 0:
            continue
        sm, ssd = _mean_sd(e2e)
        if f_pct == 0:
            f0_success = sm
        agg.append((f_pct, {
            "n_mal": n_mal, "runs": runs, "success": sm, "success_sd": ssd,
            "raw": _mean_sd(raws)[0] if raws else float("nan"),
            "p50": _mean_sd(p50s)[0], "p95": _mean_sd(p95s)[0], "p99": _mean_sd(p99s)[0],
            "hc": _mean_sd(hc)[0] if hc else float("nan"),
            "orph": _mean_sd(orph)[0] if orph else float("nan"),
        }))
    for f_pct, m in agg:
        delta = (f0_success - m["success"]) if not math.isnan(f0_success) else float("nan")
        raw_note = "" if math.isnan(m["raw"]) else f"raw-DHT {m['raw']:.1f}%"
        rows.append({
            "source": "socket", "block": "blackhole", "axis": "f_pct", "intensity": "",
            "f_pct": f_pct, "n_mal": m["n_mal"], "realized_f_pct": round(100.0 * m["n_mal"] / N, 4),
            "runs": m["runs"], "arm": "control" if f_pct == 0 else "attack",
            "honest_success_pct": m["success"], "honest_success_sd": m["success_sd"],
            "p50_ms": m["p50"], "p95_ms": m["p95"], "p99_ms": m["p99"],
            "offered_rpc_per_s": "", "measured_rpc_per_s": "",
            "ring_correct_succ_pct": m["hc"], "ring_orphans": m["orph"],
            "protocol_delta_pct": delta,
            "note": ("honest control" if f_pct == 0
                     else "systemic e2e (fallback recovers); " + raw_note).strip("; "),
        })
    return rows


def inproc_rows() -> list[dict]:
    if not INPROC_CSV.exists():
        return []
    out = []
    with open(INPROC_CSV, newline="") as f:
        for r in csv.DictReader(f):
            out.append(r)        # already in FIELDS schema; carried through verbatim
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="B7 DoS aggregate + merge (issue #48).")
    ap.add_argument("--no-plot", action="store_true")
    a = ap.parse_args()

    rows: list[dict] = []
    rows += inproc_rows()
    rows += socket_flood_rows()
    rows += socket_blackhole_rows()

    if not rows:
        print("[b7-dos] no data found — run experiments/b7_inproc.py and/or experiments/run_b7.sh first")
        return 1

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: _fmt(r.get(k, "")) if not isinstance(r.get(k), str) else r.get(k, "")
                        for k in FIELDS})
    srcs = {}
    for r in rows:
        srcs[r.get("source", "?")] = srcs.get(r.get("source", "?"), 0) + 1
    print(f"[b7-dos] wrote {OUT_CSV.relative_to(REPO_ROOT)} ({len(rows)} rows: "
          + ", ".join(f"{k}={v}" for k, v in sorted(srcs.items())) + ")")

    if not a.no_plot:
        try:
            import subprocess
            subprocess.run([sys.executable, str(REPO_ROOT / "experiments" / "plot_b7.py")], check=False)
        except Exception as e:
            print(f"[b7-dos] plot skipped: {e!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
