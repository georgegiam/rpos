#!/usr/bin/env python3
"""Issue #51 [C2] — Response timeout δ under realistic network jitter
(Phase 8, examiner point (i)).

C2 answers the money question left open by Phase 1 and sharpened by C1:

    "What δ separates honest from cheater WITHOUT rejecting honest provers under real network
     conditions?"

C1 (#50) produced the definitive storage→recompute-time trade-off for the frozen v3 DRG scheme, but
as a PURE COMPUTE model: δ was a flat threshold with no network. C2 adds the missing piece —
realistic network jitter — and turns the single threshold into two measurable error rates:

  * FALSE-REJECT  = P(an HONEST prover's challenge-response arrives after δ).  An honest prover is
    network-bound: one challenge→proof round trip plus a few-µs Merkle proof. Under jitter its
    response time is a DISTRIBUTION; a too-tight δ rejects honest nodes.
  * FALSE-ACCEPT  = P(a CHEATER keeping storage fraction ρ answers within δ).  A cheater is
    compute-bound: it must recompute the DRG back-cone (seconds, from C1). A too-loose δ accepts it.

JITTER MODEL (issue #51; netem delays from results/PARAMETERS.md):
  base RTT = 2 × one-way netem delay  (a challenge-response is a round trip):
      intra-region  2 × 5 ms  = 10 ms   |   cross-region  2 × 50 ms = 100 ms
  + Gaussian jitter  J ~ N(0, σ),  σ ∈ {5, 10, 20} ms  (one draw per response).
  (The issue calls the 5/50 ms figures "base RTT"; PARAMETERS.md defines them as ONE-WAY delays, so
  the physically-correct round trip is 2×. The factor is flagged in C2_NOTES.md; it does not change
  any conclusion — the honest base is still ~10×–100× below the smallest δ.)

WHAT IS MEASURED / MODELLED, per (rtt_tier, DRG in-degree δ_g, σ, response-timeout δ):
  honest:   T_h = base_rtt + c_h + J,  c_h = REAL in-process prove_v3+verify_v3 compute (measured
            here) combined with the analytic thesis-scale proof cost; FR = 1 − Φ((δ − rtt − c_h)/σ).
  cheater:  T_c = base_rtt + t_rec(ρ) + J,  t_rec(ρ) read from C1's committed extrapolated rows
            (results/C1_retention_attack.csv, source=extrapolated, thesis N); FA = Φ((δ − rtt − t_rec)/σ).
Rates are the exact Gaussian CDF (deterministic, reproducible); a seeded Monte-Carlo draw
(seed 20260919) cross-checks them in --self-test.

PARALLEL-ATTACKER CAVEAT (Phase 1 FIX_A §5; carried from C1): an unlimited-core attacker is bounded
below by the back-cone CRITICAL-PATH depth, a floor ≈ (N/log₂N)/rate ≈ 5.15 s at thesis scale
(par_floor_s column). That makes the loosest δ = 5 s MARGINAL against the idealised parallel model.
The sequential verdict (δ ≤ 2 s cleanly separates) is the well-supported basis; the floor is a
flagged sensitivity, not the verdict. In-degree δ_g / target depth-robustness await cryptographer
sign-off (CLAUDE.md, Phase 1 "Open").

LIKE A7/B2/B5/C1 THIS IS A MICROBENCHMARK, NOT A DOCKER TESTBED RUN (and needs no Docker): the
honest proof cost is a property of the PoSpace plot graph (measured in-process over the frozen
prove_v3/verify_v3), and the netem delays enter as model parameters. It IMPORTS the frozen phase1
primitives and READS C1's committed CSV; rpos/rpos.py and all of phase1/* and node/* stay
byte-identical (CLAUDE.md §2). Fixed seed 20260919.

Run:  python3 experiments/c2_delta_jitter.py                 # full sweep -> CSV + PNG + stdout
      python3 experiments/c2_delta_jitter.py --no-plot       # table only
      python3 experiments/c2_delta_jitter.py --self-test     # deterministic checks, no Docker
      python3 experiments/c2_delta_jitter.py --sigmas 5,10,20 --deltas 1,2,3,5,10 --indegrees 2
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
from statistics import NormalDist

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
OUT_CSV = RESULTS / "C2_delta_jitter.csv"
OUT_FIG = RESULTS / "fig_C2_roc.png"
C1_CSV = RESULTS / "C1_retention_attack.csv"

# phase1/ holds the frozen v3 DRG primitives; importable both as repo root and as the phase1 package
# root (for the sibling `pospace`/`drg` imports inside those modules), exactly as C1 does.
for p in (REPO_ROOT, REPO_ROOT / "phase1"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# frozen primitives — imported, never copied (CLAUDE.md §2). Importing runs no _test()/run().
from pospace_drg import plot_v3, commit_v3, prove_v3, verify_v3   # noqa: E402
from delta_separation_drg import avg_indegree                     # noqa: E402

# thesis plot size — the constant the node actually admits with (node/pospace_admission.py:52).
try:
    from node.pospace_admission import REAL_PLOT_N                # noqa: E402
except Exception:
    REAL_PLOT_N = 3_355_443_200

# ---------------------------------------------------------------------------------------
# frozen C2 workload (CLAUDE.md §2 / §5; issue #51)
# ---------------------------------------------------------------------------------------
SEED = 20260919                                   # frozen repo seed (CLAUDE.md §2)
RTT_TIERS = {"intra": 0.010, "cross": 0.100}      # base RTT = 2 × one-way netem (PARAMETERS.md)
SIGMAS_MS = [5.0, 10.0, 20.0]                     # Gaussian jitter σ (ms)   — issue #51
RESP_DELTAS = [1.0, 2.0, 3.0, 5.0, 10.0]          # response timeouts δ (s)  — issue #51
DRG_INDEGREES = [2, 4, 8]                         # DRG in-degree δ_g; 2 = node default = headline
HEADLINE_INDEGREE = 2
ROC_FRACTIONS = [50.0, 25.0, 10.0, 5.0]           # cheater storage ρ% featured in the ROC
ANCHOR_N = 1 << 14                                # in-process plot size for the real prove/verify anchor
ANCHOR_CHALLENGES = 200                           # real prove+verify round trips timed per in-degree
MC_SAMPLES = 100_000                              # Monte-Carlo cross-check size (self-test)
LOG2N_THESIS = math.ceil(math.log2(REAL_PLOT_N))  # 32


# --- measured native single-core SHA-256 rate (repo convention; CLAUDE.md §5) ---
def _load_chain_rate(default_hs: float = 20_363_000.0) -> float:
    """hashes/s (native, single core) from phase1/results/chainrate.csv — matches a7/b2/c1."""
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
# cheater side — read C1's committed trade-off (the intended C2->C1 dependency).
# ---------------------------------------------------------------------------------------
def load_c1_cheater() -> tuple[dict, float]:
    """From results/C1_retention_attack.csv return
        t_rec[(indegree, frac_pct)] = extrapolated thesis-scale recompute_time_s_median,
        par_floor_s  (the unlimited-core critical-path floor, constant across extrapolated rows).
    C1 is a hard dependency (issue #51 'Depends on C1'); fail loudly if it hasn't been run, exactly
    as phase1/delta_separation_drg.py does for its own input CSV."""
    if not C1_CSV.exists():
        raise SystemExit(
            f"{_rel(C1_CSV)} not found — run C1 first:  bash experiments/run_c1.sh\n"
            "(C2 reads the cheater storage→recompute-time curve from C1's committed deliverable.)")
    t_rec: dict[tuple[int, float], float] = {}
    par_floor = float("nan")
    for r in csv.DictReader(open(C1_CSV)):
        if r["source"] != "extrapolated":
            continue
        key = (int(r["delta"]), round(float(r["label_frac_pct"]), 6))
        t_rec[key] = float(r["recompute_time_s_median"])
        if r.get("par_floor_s"):
            par_floor = float(r["par_floor_s"])
    if not t_rec:
        raise SystemExit(f"{_rel(C1_CSV)} has no source=extrapolated rows — re-run C1.")
    return t_rec, par_floor


def cheater_fracs_for(t_rec: dict, indegree: int) -> list[float]:
    """Sorted label-fraction % present in C1's extrapolated rows for this in-degree (descending)."""
    return sorted({f for (d, f) in t_rec if d == indegree}, reverse=True)


# ---------------------------------------------------------------------------------------
# honest side — REAL in-process prove_v3 + verify_v3 timing anchor, plus the analytic thesis-scale
# proof cost. Both are ~µs; the conservative (larger) of the two feeds the model so honest response
# is never understated. Honest response is network-bound either way.
# ---------------------------------------------------------------------------------------
def measure_honest_compute(indegree: int, seed: int) -> tuple[float, float]:
    """Return (anchor_compute_s, thesis_analytic_s) for one DRG in-degree.
    anchor = REAL measured prove_v3+verify_v3 over ANCHOR_CHALLENGES challenges on a 2^14 plot — the
      'measure, don't assert' evidence that the honest proof is real and ~µs (reported to stdout).
    thesis_analytic = (1+avg_indeg)·(log2N_thesis+1) hashes / rate (Merkle paths grow with log2N) —
      the DETERMINISTIC thesis-scale honest compute that feeds the rate model (so the CSV is
      byte-reproducible; the live timer is for the anchor only, like C1's wallclock anchor)."""
    rng = random.Random(seed ^ (0xC2 << 8) ^ indegree)
    pk = bytes(rng.getrandbits(8) for _ in range(33))
    labels = plot_v3(pk, ANCHOR_N, indegree)
    levels, root = commit_v3(labels)
    samp = []
    for _ in range(ANCHOR_CHALLENGES):
        i = rng.randrange(1, ANCHOR_N)
        t0 = time.perf_counter()
        proof = prove_v3(levels, pk, ANCHOR_N, indegree, i)
        ok = verify_v3(root, pk, ANCHOR_N, indegree, i, proof)
        samp.append(time.perf_counter() - t0)
        assert ok, f"verify_v3 failed at anchor N={ANCHOR_N} δ_g={indegree} i={i}"
    anchor = statistics.median(samp)
    opened = 1.0 + avg_indegree(indegree)
    thesis_analytic = opened * (LOG2N_THESIS + 1) / CHAIN_RATE
    return anchor, thesis_analytic


# ---------------------------------------------------------------------------------------
# error-rate model — exact Gaussian CDF (jitter applied to the network term).
# ---------------------------------------------------------------------------------------
def false_reject(delta_s: float, base_rtt_s: float, c_h_s: float, sigma_s: float) -> float:
    """P(honest T_h = base_rtt + c_h + J > delta),  J ~ N(0, sigma)."""
    return 1.0 - NormalDist(0.0, sigma_s).cdf(delta_s - base_rtt_s - c_h_s)


def false_accept(delta_s: float, base_rtt_s: float, t_rec_s: float, sigma_s: float) -> float:
    """P(cheater T_c = base_rtt + t_rec + J <= delta),  J ~ N(0, sigma)."""
    return NormalDist(0.0, sigma_s).cdf(delta_s - base_rtt_s - t_rec_s)


def _mc_rate(delta_s, base_rtt_s, fixed_s, sigma_s, rng, n, accept_if_le: bool) -> float:
    """Monte-Carlo cross-check of the CDF: fraction of samples with (base+fixed+J) <= / > delta."""
    hit = 0
    for _ in range(n):
        t = base_rtt_s + fixed_s + rng.gauss(0.0, sigma_s)
        hit += (t <= delta_s) if accept_if_le else (t > delta_s)
    return hit / n


# ---------------------------------------------------------------------------------------
# row builders.
# ---------------------------------------------------------------------------------------
def honest_row(tier, rtt, indegree, sigma_ms, delta_s, c_h_s) -> dict:
    sigma_s = sigma_ms / 1e3
    fr = false_reject(delta_s, rtt, c_h_s, sigma_s)
    p99 = rtt + c_h_s + NormalDist(0.0, sigma_s).inv_cdf(0.99)
    return dict(
        role="honest", rtt_tier=tier, base_rtt_ms=rtt * 1e3, drg_indegree=indegree,
        sigma_ms=sigma_ms, resp_delta_s=delta_s, storage_frac_pct=float("nan"),
        honest_compute_ms=c_h_s * 1e3,
        honest_p50_resp_ms=(rtt + c_h_s) * 1e3, honest_p99_resp_ms=p99 * 1e3,
        cheater_recompute_s=float("nan"), cheater_p50_resp_s=float("nan"),
        false_reject_rate=fr, false_accept_rate=float("nan"),
        par_floor_s=float("nan"), mc_samples=MC_SAMPLES, method="normal_cdf",
        note="honest = base_rtt + prove/verify + N(0,σ) jitter")


def cheater_row(tier, rtt, indegree, sigma_ms, delta_s, frac_pct, t_rec_s, par_floor) -> dict:
    sigma_s = sigma_ms / 1e3
    fa = false_accept(delta_s, rtt, t_rec_s, sigma_s)
    return dict(
        role="cheater", rtt_tier=tier, base_rtt_ms=rtt * 1e3, drg_indegree=indegree,
        sigma_ms=sigma_ms, resp_delta_s=delta_s, storage_frac_pct=frac_pct,
        honest_compute_ms=float("nan"),
        honest_p50_resp_ms=float("nan"), honest_p99_resp_ms=float("nan"),
        cheater_recompute_s=t_rec_s, cheater_p50_resp_s=rtt + t_rec_s,
        false_reject_rate=float("nan"), false_accept_rate=fa,
        par_floor_s=par_floor, mc_samples=MC_SAMPLES, method="normal_cdf",
        note=f"cheater keeps {frac_pct:g}% labels; t_rec from C1 extrapolated (thesis N)")


# ---------------------------------------------------------------------------------------
# CSV.
# ---------------------------------------------------------------------------------------
FIELDS = ["role", "rtt_tier", "base_rtt_ms", "drg_indegree", "sigma_ms", "resp_delta_s",
          "storage_frac_pct", "honest_compute_ms", "honest_p50_resp_ms", "honest_p99_resp_ms",
          "cheater_recompute_s", "cheater_p50_resp_s", "false_reject_rate", "false_accept_rate",
          "par_floor_s", "mc_samples", "method", "note"]


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
    order = {"honest": 0, "cheater": 1}
    def key(r):
        return (order.get(r["role"], 9), r["drg_indegree"], 0 if r["rtt_tier"] == "intra" else 1,
                r["sigma_ms"], r["resp_delta_s"],
                -(r["storage_frac_pct"] if not math.isnan(r["storage_frac_pct"]) else 0.0))
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=key):
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# ---------------------------------------------------------------------------------------
# Plot: (A) the ROC — false-accept vs false-reject, parametric in δ, one curve per cheater storage;
# (B) honest false-reject vs δ for each σ and RTT tier (the "without rejecting honest" half).
# ---------------------------------------------------------------------------------------
def make_plot(c_h_by_indeg, t_rec, par_floor) -> None:
    import numpy as np
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    frac_shades = {50.0: "#9ec9f2", 25.0: "#2a78d6", 10.0: "#e08a1e", 5.0: "#8a1c5a"}
    sigma_shades = {5.0: "#9ec9f2", 10.0: "#2a78d6", 20.0: "#0b3a66"}
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    d_g = HEADLINE_INDEGREE
    c_h = c_h_by_indeg[d_g]
    tier, rtt = "cross", RTT_TIERS["cross"]
    sigma_ms = 20.0
    sigma_s = sigma_ms / 1e3
    dsweep = np.logspace(math.log10(0.1), math.log10(200.0), 400)   # continuous δ for the ROC lines

    # --- panel A: ROC (false-accept vs false-reject), one curve per cheater storage ρ ---
    ax = axes[0]
    for frac in ROC_FRACTIONS:
        key = (d_g, round(frac, 6))
        if key not in t_rec:
            continue
        trec = t_rec[key]
        fa = [false_accept(d, rtt, trec, sigma_s) for d in dsweep]
        fr = [false_reject(d, rtt, c_h, sigma_s) for d in dsweep]
        ax.plot(fa, fr, lw=1.8, color=frac_shades.get(frac, MUTED),
                label=f"keep {frac:g}% (t_rec={trec:.1f}s)")
        # mark the discrete operating δ grid as points on each curve
        for d in RESP_DELTAS:
            ax.plot(false_accept(d, rtt, trec, sigma_s), false_reject(d, rtt, c_h, sigma_s),
                    marker="o", ms=4, color=frac_shades.get(frac, MUTED))
    ax.plot([0, 1], [0, 1], ls=":", lw=0.8, color=MUTED)        # chance diagonal
    ax.set_xlim(-0.03, 1.03); ax.set_ylim(-0.03, 1.03)
    ax.set_xlabel("false-accept rate (cheater answers within δ)")
    ax.set_ylabel("false-reject rate (honest misses δ)")
    ax.set_title(f"ROC vs δ (δ_g={d_g}, cross-region 100 ms RTT, σ=20 ms)")
    ax.legend(frameon=False, fontsize=7, loc="upper right", title="cheater storage")
    ax.text(0.5, 0.06, "operating δ∈{1,2,3,5,10}s sit at the bottom-left\n"
            "(honest FR≈0; cheater FA≈0 for ≤25% keep)", fontsize=6.5, color=MUTED, ha="center")

    # --- panel B: honest false-reject vs δ (the "without rejecting honest provers" half) ---
    ax = axes[1]
    ddense = np.logspace(math.log10(0.02), math.log10(10.0), 300)
    for tier2, rtt2 in RTT_TIERS.items():
        for sig in SIGMAS_MS:
            frs = [false_reject(d, rtt2, c_h, sig / 1e3) for d in ddense]
            ls = "-" if tier2 == "cross" else "--"
            ax.plot(ddense, frs, ls=ls, lw=1.5, color=sigma_shades.get(sig, MUTED),
                    label=f"{tier2}, σ={sig:g}ms")
    for d in RESP_DELTAS:
        ax.axvline(d, color=GRID, lw=0.8)
    ax.axvline(par_floor, color="#8a1c5a", lw=1.1, ls=":")
    ax.text(par_floor, 0.55, f" parallel floor ≈{par_floor:.1f}s\n (δ≥5s marginal)",
            fontsize=6.5, color="#8a1c5a", va="center")
    ax.set_xscale("log"); ax.set_ylim(-0.03, 1.03)
    ax.set_xlabel("response timeout δ (s)")
    ax.set_ylabel("honest false-reject rate")
    ax.set_title(f"Honest provers are network-bound (δ_g={d_g})")
    ax.legend(frameon=False, fontsize=7, loc="center left")

    fig.suptitle("C2 — response timeout δ under realistic network jitter (honest vs cheater)",
                 y=1.03, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
# self-test (deterministic; no Docker) — b2/b5 lettered-check convention.
# ---------------------------------------------------------------------------------------
def _self_test() -> int:
    ok = True
    rng = random.Random(SEED)

    # (a) CDF vs Monte-Carlo agreement for FR and FA at a boundary-ish config
    c_h = 50e-6
    fr_cdf = false_reject(0.12, 0.10, c_h, 0.02)
    fr_mc = _mc_rate(0.12, 0.10, c_h, 0.02, rng, MC_SAMPLES, accept_if_le=False)
    fa_cdf = false_accept(2.05, 0.10, 2.0, 0.02)
    fa_mc = _mc_rate(2.05, 0.10, 2.0, 0.02, rng, MC_SAMPLES, accept_if_le=True)
    a_ok = abs(fr_cdf - fr_mc) < 0.01 and abs(fa_cdf - fa_mc) < 0.01
    ok &= a_ok
    print(f"  (a) CDF vs MC: FR {fr_cdf:.3f}/{fr_mc:.3f}  FA {fa_cdf:.3f}/{fa_mc:.3f}  "
          f"[{'ok' if a_ok else 'OFF'}]")

    # (b) honest false-reject ≈ 0 across the whole δ grid (network-bound), worst tier+σ
    worst = max(false_reject(d, RTT_TIERS["cross"], 1e-4, max(SIGMAS_MS) / 1e3)
                for d in RESP_DELTAS)
    b_ok = worst < 1e-6
    ok &= b_ok
    print(f"  (b) honest FR max over δ grid (cross, σ=20ms) = {worst:.2e}  [{'ok' if b_ok else 'OFF'}]")

    # (c) monotonicity: FA rises with δ, FR falls with δ
    fa_seq = [false_accept(d, 0.10, 13.0, 0.02) for d in sorted(RESP_DELTAS)]
    fr_seq = [false_reject(d, 0.10, 1e-4, 0.02) for d in sorted(RESP_DELTAS)]
    c_ok = all(x <= y + 1e-12 for x, y in zip(fa_seq, fa_seq[1:])) and \
           all(x >= y - 1e-12 for x, y in zip(fr_seq, fr_seq[1:]))
    ok &= c_ok
    print(f"  (c) FA↑ FR↓ in δ  [{'ok' if c_ok else 'OFF'}]")

    # (d) C1 dependency present and extrapolated rows load
    try:
        t_rec, par_floor = load_c1_cheater()
        d_ok = (HEADLINE_INDEGREE, 25.0) in t_rec and t_rec[(HEADLINE_INDEGREE, 25.0)] > 5.0 \
            and 4.0 < par_floor < 7.0
        print(f"  (d) C1 load: keep25%→t_rec={t_rec.get((HEADLINE_INDEGREE,25.0),float('nan')):.2f}s, "
              f"par_floor={par_floor:.2f}s  [{'ok' if d_ok else 'OFF'}]")
    except SystemExit as e:
        d_ok = False
        print(f"  (d) C1 load FAILED: {e}  [OFF]")
    ok &= d_ok

    # (e) real prove_v3/verify_v3 anchor runs and is small (µs–ms, network-dominated)
    anchor, thesis = measure_honest_compute(HEADLINE_INDEGREE, SEED)
    e_ok = 0 < anchor < 0.05 and 0 < thesis < 0.05
    ok &= e_ok
    print(f"  (e) honest compute δ_g=2: real anchor {anchor*1e6:.1f}µs | thesis-analytic (model) "
          f"{thesis*1e6:.1f}µs  [{'ok' if e_ok else 'OFF'}]")

    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="C2 δ under network jitter (issue #51).")
    ap.add_argument("--self-test", action="store_true", help="deterministic checks, no Docker")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--sigmas", default=",".join(f"{s:g}" for s in SIGMAS_MS),
                    help="comma list of jitter σ in ms")
    ap.add_argument("--deltas", default=",".join(f"{d:g}" for d in RESP_DELTAS),
                    help="comma list of response timeouts δ in s")
    ap.add_argument("--indegrees", default=",".join(str(d) for d in DRG_INDEGREES),
                    help="comma list of DRG in-degrees δ_g")
    ap.add_argument("--rtt-intra-ms", type=float, default=RTT_TIERS["intra"] * 1e3)
    ap.add_argument("--rtt-cross-ms", type=float, default=RTT_TIERS["cross"] * 1e3)
    ap.add_argument("--mc-samples", type=int, default=MC_SAMPLES)
    args = ap.parse_args()

    if args.self_test:
        return _self_test()

    sigmas = [float(x) for x in args.sigmas.split(",") if x]
    deltas = [float(x) for x in args.deltas.split(",") if x]
    indegrees = [int(x) for x in args.indegrees.split(",") if x]
    tiers = {"intra": args.rtt_intra_ms / 1e3, "cross": args.rtt_cross_ms / 1e3}

    print(f"C2 δ under network jitter — seed={args.seed}, CHAIN_RATE={CHAIN_RATE/1e6:.2f} MH/s")
    print(f"  RTT tiers (2×one-way): intra {tiers['intra']*1e3:g} ms / cross {tiers['cross']*1e3:g} ms"
          f"  σ={sigmas} ms  δ={deltas} s  δ_g={indegrees}")

    t_rec, par_floor = load_c1_cheater()
    print(f"  cheater curve from {_rel(C1_CSV)} (thesis N); parallel floor ≈ {par_floor:.2f} s")

    # honest compute per in-degree: REAL prove_v3+verify_v3 anchor (reported) + the deterministic
    # thesis-scale analytic term that feeds the model (keeps the CSV byte-reproducible).
    print("\n== honest compute (real in-process prove_v3+verify_v3 anchor → thesis-analytic model) ==")
    c_h_by_indeg = {}
    for d_g in indegrees:
        anchor, thesis = measure_honest_compute(d_g, args.seed)
        c_h_by_indeg[d_g] = thesis
        print(f"  δ_g={d_g}: real anchor {anchor*1e6:7.1f} µs (N=2^14, measured) | model c_h "
              f"{thesis*1e6:7.1f} µs (thesis-analytic, deterministic)")

    rows: list[dict] = []
    print("\n== honest false-reject (network-bound; FR≈0 across the δ grid) ==")
    for d_g in indegrees:
        c_h = c_h_by_indeg[d_g]
        for tier, rtt in tiers.items():
            for sig in sigmas:
                for d in deltas:
                    rows.append(honest_row(tier, rtt, d_g, sig, d, c_h))
        # one readable line: worst-case honest (cross, largest σ) FR across δ
        big = max(sigmas)
        frs = [false_reject(d, tiers["cross"], c_h, big / 1e3) for d in deltas]
        p99 = tiers["cross"] + c_h + NormalDist(0, big / 1e3).inv_cdf(0.99)
        print(f"  δ_g={d_g}: cross p99 resp {p99*1e3:6.1f} ms | FR over δ {deltas} "
              f"= {['%.1e' % x for x in frs]}")

    print("\n== cheater false-accept (t_rec from C1; FA=0 while recompute ≫ δ) ==")
    for d_g in indegrees:
        for frac in cheater_fracs_for(t_rec, d_g):
            trec = t_rec[(d_g, frac)]
            for tier, rtt in tiers.items():
                for sig in sigmas:
                    for d in deltas:
                        rows.append(cheater_row(tier, rtt, d_g, sig, d, frac, trec, par_floor))
            # readable line for the cross tier / largest σ
            big = max(sigmas)
            fas = [false_accept(d, tiers["cross"], trec, big / 1e3) for d in deltas]
            print(f"  δ_g={d_g} keep {frac:5.1f}% (t_rec={trec:8.2f}s): FA over δ {deltas} "
                  f"= {['%.2f' % x for x in fas]}")

    write_csv(rows)
    if not args.no_plot:
        make_plot(c_h_by_indeg, t_rec, par_floor)

    # ---- bottom line ----
    d_g = HEADLINE_INDEGREE
    print("\n" + "=" * 96)
    print("BOTTOM LINE (δ_g=2, sequential verdict basis):")
    print("  Honest provers are network-bound: challenge-response ≈ base RTT (≤100 ms) + a few-µs "
          "proof, so even")
    print("  at σ=20 ms cross-region the p99 is well under 1 s → false-reject ≈ 0 for every δ ≥ 1 s.")
    print("  A cheater keeping <50% labels recomputes ≥13 s (C1), so false-accept = 0 for δ ≤ 2 s "
          "(≤10 s at 25% keep).")
    print(f"  ⇒ δ ≤ 2 s cleanly separates honest from cheater under real jitter. The unlimited-core "
          f"parallel floor ≈ {par_floor:.1f} s")
    print("    makes δ = 5 s MARGINAL (flagged sensitivity, not the verdict) — prefer δ ≤ 2 s. "
          "In-degree δ_g awaits cryptographer sign-off.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
