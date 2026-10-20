#!/usr/bin/env python3
"""Issue #52 [C3] — Detection probability vs challenges per round
(Phase 8, examiner point (i)).

C3 answers the operational follow-up to C1/C2:

    "How many periodic challenges does it take to catch a cheater with high probability?"

C1 (#50) produced the storage→recompute-time trade-off for the frozen v3 DRG scheme; C2 (#51)
turned it into false-accept/false-reject rates vs a response timeout δ under network jitter. Both
are per-CHALLENGE statements. The node, however, challenges peers PERIODICALLY (~every 5 s) and
evicts a peer after MAX_FAILS = 3 CONSECUTIVE failed challenges (node/pospace_admission.py). C3
closes the loop: it derives the per-challenge failure probability p_fail(ρ) and the detection /
eviction probability after c challenges.

PER-CHALLENGE FAILURE PROBABILITY — two definitions, compared (the issue's "analytical vs empirical,
report the gap"):

  * TIME-GATED (primary, EMPIRICAL).  One challenge opens a random leaf i plus its DRG parents; the
    cheater who kept label-fraction ρ must recompute the back-cone of any opened label it discarded.
    The challenge CATCHES the cheater iff that recompute exceeds δ at thesis scale:
        p_fail(ρ,δ,δ_g) = P_over_random_i[ φ_i · N_thesis / CHAIN_RATE > δ ],
        where φ_i = back_cone(i,ρ)/N_measured is the per-challenge back-cone fraction (C1's
        measure_config quantity), measured here over MANY challenges (a tail fraction needs far more
        samples than C1's median). Equivalently φ_i > φ* = δ·CHAIN_RATE/N_thesis (≈ 0.0121 at δ=2 s).

  * COVERAGE (ANALYTICAL reference, closed form).  The naive PoRep intuition: any challenge that
    opens a label the cheater discarded is a catch:
        p_cov(ρ) = 1 − ρ^(1 + avg_indegree(δ_g)).
    This is a STRICT UPPER BOUND on p_fail (⇒ {recompute>δ} ⊂ {opened a hole}). The GAP between the
    two is the cheater's CHEAP holes — discarded labels whose back-cone recomputes within δ — and is
    MAXIMAL at ρ=50% (coverage says most challenges hit a hole, but each recomputes in sub-ms ≪ δ, so
    a timeout never catches it). The headline: DETECTION IS RECOMPUTE-TIME BOUND, NOT COVERAGE-BOUND.

DETECTION & EVICTION after c i.i.d. challenges (the node draws one fresh uniform leaf per round →
Bernoulli(p_fail), node/pospace_admission.py):
  * detection (≥1 failed challenge, the issue's formula):  P_detect(c) = 1 − (1 − p_fail)^c.
  * eviction (the node's REAL policy = 3 CONSECUTIVE fails): absorbing Markov chain on the fail
    streak {0,1,2,evicted}; P_evict(c) and the expected challenges to a run of MAX_FAILS.
  * expected challenges: first fail E[T1]=1/p; first run of r=MAX_FAILS E[Tr]=(1−p^r)/((1−p)p^r).
    Wall-clock = E · challenge-period (~5 s, run_ring_node.py).

LIKE A7/B2/B5/C1/C2 THIS IS A MICROBENCHMARK, NOT A DOCKER TESTBED RUN (and needs no Docker): the
back-cone is a property of the frozen DRG graph (traversed in-process via the frozen backcone_mask),
and the eviction curve is exact probability from the node's policy constants. It IMPORTS the frozen
phase1 primitives and READS node/pospace_admission for REAL_PLOT_N / MAX_FAILS; rpos/rpos.py and all
of phase1/* and node/* stay byte-identical (CLAUDE.md §2). Fixed seed 20260919.

CAVEATS (flag, don't hide — CLAUDE.md §2; carried from C1/FIX_A):
  * φ is taken flat across the measured 2^18–2^22 and applied ~800× beyond it to thesis N, relying on
    DRSample's asymptotic depth-robustness, not a re-proof. C3 reports p_fail PER MEASURED N as a band
    (the knee at ρ≈25% is a finite-size / percolation regime where per-N spread is widest).
  * the unlimited-core parallel floor ≈ (N/log₂N)/rate ≈ 5.15 s makes a loose δ marginal (C2); C3's
    headline δ = 2 s is below it.
  * in-degree δ_g / target depth-robustness await cryptographer sign-off (CLAUDE.md, Phase 1 "Open").

Run:  python3 experiments/c3_detection.py                 # full sweep -> CSV + PNG + stdout
      python3 experiments/c3_detection.py --no-plot       # table only
      python3 experiments/c3_detection.py --self-test     # deterministic checks, no Docker
      python3 experiments/c3_detection.py --quick         # drop N=2^22 (fast iteration)
      python3 experiments/c3_detection.py --fractions 50,25,10 --indegrees 2 --challenges 2000
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

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
OUT_CSV = RESULTS / "C3_detection.csv"
OUT_FIG = RESULTS / "fig_C3_detection.png"

# phase1/ holds the frozen v3 DRG retention-attack physics; importable both as repo root and as the
# phase1 package root (for the sibling pospace/drg imports inside those modules), exactly as C1/C2 do.
for p in (REPO_ROOT, REPO_ROOT / "phase1"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# frozen primitives — imported, never copied (CLAUDE.md §2). Importing runs no _test()/run().
from attack_v3_retain import parent_table, backcone_mask            # noqa: E402
from delta_separation_drg import avg_indegree                       # noqa: E402
from drg import parents                                             # noqa: E402

# thesis plot size + the node's eviction policy of record (node/pospace_admission.py).
try:
    from node.pospace_admission import REAL_PLOT_N, MAX_FAILS       # noqa: E402
except Exception:                                                   # keep dependency-light
    REAL_PLOT_N = 3_355_443_200
    MAX_FAILS = 3

# ---------------------------------------------------------------------------------------
# frozen C3 workload (CLAUDE.md §2 / §5; issue #52)
# ---------------------------------------------------------------------------------------
SEED = 20260919                                   # frozen repo seed (CLAUDE.md §2; phase1 used 1)
NS = [1 << 18, 1 << 20, 1 << 22]                  # measured sizes (the Phase-1 grid → φ band)
INDEGREES = [2, 4, 8]                             # DRG in-degree δ_g; 2 = node default = headline
HEADLINE_INDEGREE = 2
# label fractions ρ the cheater keeps (%). The knee sits near 25% at δ_g=2, so the grid is dense
# there (20/25/30/33) with 50% (escapes) and 10% (always caught) bracketing it.
FRACTIONS = [50.0, 33.0, 30.0, 25.0, 20.0, 10.0]
CHALLENGE_COUNTS = [1, 5, 10, 20, 50]            # c — challenges per round-window (issue #52)
RESP_DELTA = 2.0                                  # response timeout δ (s); node test-scale = headline
CHALLENGE_PERIOD_S = 5.0                          # periodic challenge cadence (run_ring_node.py)
# per-N challenge sample counts: p_fail is a TAIL fraction, so we sample far more than C1's median
# cadence. Count scales down with N to bound the back-cone-BFS wall-clock (cost grows with N).
CHALLENGES_BY_N = {1 << 18: 3000, 1 << 20: 1500, 1 << 22: 700}
DEFAULT_CHALLENGES = 1500


# --- measured native single-core SHA-256 rate (repo convention; CLAUDE.md §5) ---
def _load_chain_rate(default_hs: float = 20_363_000.0) -> float:
    """hashes/s (native, single core) from phase1/results/chainrate.csv — matches a7/b2/c1/c2."""
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


def phi_star(delta_s: float) -> float:
    """Per-challenge back-cone FRACTION above which the thesis-scale recompute exceeds δ:
        φ·N_thesis/rate > δ  ⇔  φ > δ·rate/N_thesis.  ≈ 0.012137 at δ=2 s."""
    return delta_s * CHAIN_RATE / REAL_PLOT_N


def _pct(xs, q):
    """Nearest-rank percentile (q in [0,1]); mirrors attack_v3_retain.pct / c1_retention._pct."""
    if not xs:
        return float("nan")
    s = sorted(xs)
    k = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return s[k]


# ---------------------------------------------------------------------------------------
# storage model — LABEL fraction kept, evenly spaced (copied idiom from c1_retention.retained_mask;
# for 1/integer fractions this coincides with the frozen 'every s-th label' stride).
# ---------------------------------------------------------------------------------------
def retained_mask(N: int, label_frac: float) -> np.ndarray:
    m = max(1, min(N, int(round(label_frac * N))))
    mask = np.zeros(N, dtype=bool)
    if m >= N:
        mask[:] = True
    else:
        idx = np.unique(np.round(np.linspace(0, N - 1, m)).astype(np.int64))
        mask[idx] = True
    return mask


# ---------------------------------------------------------------------------------------
# per-challenge back-cone fractions φ_i over a FIXED set of challenge leaves (paired sampling: the
# same leaves i are reused across all fractions at a given (N, δ_g), so only the retained mask moves).
# ---------------------------------------------------------------------------------------
def sample_phis(N: int, pk: bytes, tab: np.ndarray, opened_list, mask) -> list[float]:
    phis = []
    for opened in opened_list:
        seen = backcone_mask(opened, mask, tab)
        phis.append(int(seen.sum()) / N)
    return phis


def build_opened(N: int, delta_g: int, pk: bytes, idxs) -> list:
    """Opened node set per challenge = leaf i + its DRG parents (mask-independent → precompute once)."""
    return [np.array([i] + parents(i, pk, delta_g), dtype=np.int64) for i in idxs]


# ---------------------------------------------------------------------------------------
# detection (≥1 fail) and eviction (run of MAX_FAILS consecutive fails) probabilities.
# ---------------------------------------------------------------------------------------
def p_detect(p: float, c: int) -> float:
    """P(at least one failed challenge in c i.i.d. challenges)."""
    return 1.0 - (1.0 - p) ** c


def p_evict(p: float, c: int, r: int = MAX_FAILS) -> float:
    """P(a run of r consecutive fails within c challenges). Exact absorbing Markov chain on the fail
    streak {0,1,..,r-1, r=evicted}; a pass resets the streak to 0, a fail extends it (pospace_
    admission: fail_counts reset on pass / +1 on fail / evict at >=MAX_FAILS)."""
    q = 1.0 - p
    s = [1.0] + [0.0] * r
    for _ in range(c):
        ns = [0.0] * (r + 1)
        ns[r] += s[r]                       # stay evicted (absorbing)
        for k in range(r):
            ns[0] += q * s[k]               # pass -> reset streak
            ns[k + 1] += p * s[k]           # fail -> extend (k+1==r => evicted)
        s = ns
    return s[r]


def _no_run_recurrence(p: float, c: int, r: int = MAX_FAILS) -> float:
    """Scalar recurrence for N(c)=P(no run of r in c): N(c)=N(c-1)-(1-p)p^r N(c-r-1). Self-test only."""
    N = [1.0] * (r + 1)
    N[r] = 1.0 - p ** r
    for n in range(r + 1, c + 1):
        N.append(N[n - 1] - (1.0 - p) * (p ** r) * N[n - r - 1])
    return N[c] if c <= len(N) - 1 else N[-1]


def _mc_evict(p: float, c: int, rng: random.Random, trials: int, r: int = MAX_FAILS) -> float:
    """Monte-Carlo cross-check of p_evict: fraction of trials reaching a run of r within c."""
    hit = 0
    for _ in range(trials):
        streak = 0
        done = False
        for _ in range(c):
            streak = streak + 1 if rng.random() < p else 0
            if streak >= r:
                done = True
                break
        hit += done
    return hit / trials


def e_first_fail(p: float) -> float:
    return float("inf") if p <= 0 else 1.0 / p


def e_first_run(p: float, r: int = MAX_FAILS) -> float:
    """Expected challenges to the first run of r consecutive fails: (1-p^r)/((1-p)p^r); →r as p→1."""
    if p <= 0:
        return float("inf")
    if p >= 1.0:
        return float(r)
    return (1.0 - p ** r) / ((1.0 - p) * (p ** r))


# ---------------------------------------------------------------------------------------
# row builder.
# ---------------------------------------------------------------------------------------
def metric_row(source, delta_g, frac_pct, N_measured, challenges, phis, p_cov, phi_s,
               method, note="") -> dict:
    """One CSV row. For empirical rows p_fail is the time-gated tail fraction of `phis`; for analytic
    rows pass phis=None and the detection/eviction columns are driven by p_cov (the coverage model)."""
    if phis is not None:
        M = len(phis)
        pf = sum(1 for x in phis if x > phi_s) / M if M else float("nan")
        ci = 1.96 * math.sqrt(pf * (1.0 - pf) / M) if M else float("nan")
        phi_med, phi_p99 = statistics.median(phis), _pct(phis, 0.99)
    else:
        M = 0
        pf = p_cov                                   # analytic: detection driven by coverage p_fail
        ci = float("nan")
        phi_med = phi_p99 = float("nan")
    row = dict(
        source=source, drg_indegree=delta_g, storage_frac_pct=frac_pct,
        N_measured=N_measured, challenges=M if phis is not None else 0,
        phi_median=phi_med, phi_p99=phi_p99, phi_star=phi_s, resp_delta_s=RESP_DELTA,
        p_fail=pf, p_fail_ci=ci, p_cov=p_cov,
        e_challenges_first_fail=e_first_fail(pf), e_challenges_evict=e_first_run(pf),
        e_wall_first_fail_s=e_first_fail(pf) * CHALLENGE_PERIOD_S,
        e_wall_evict_s=e_first_run(pf) * CHALLENGE_PERIOD_S,
        challenge_period_s=CHALLENGE_PERIOD_S, max_fails=MAX_FAILS, seed=SEED,
        method=method, note=note)
    for c in CHALLENGE_COUNTS:
        row[f"p_detect_{c}"] = p_detect(pf, c)
    for c in CHALLENGE_COUNTS:
        row[f"p_evict_{c}"] = p_evict(pf, c)
    return row


# ---------------------------------------------------------------------------------------
# CSV.
# ---------------------------------------------------------------------------------------
FIELDS = (["source", "drg_indegree", "storage_frac_pct", "N_measured", "challenges",
           "phi_median", "phi_p99", "phi_star", "resp_delta_s",
           "p_fail", "p_fail_ci", "p_cov"]
          + [f"p_detect_{c}" for c in CHALLENGE_COUNTS]
          + [f"p_evict_{c}" for c in CHALLENGE_COUNTS]
          + ["e_challenges_first_fail", "e_challenges_evict",
             "e_wall_first_fail_s", "e_wall_evict_s",
             "challenge_period_s", "max_fails", "seed", "method", "note"])


def _fmt(v) -> str:
    if isinstance(v, float):
        if math.isnan(v):
            return ""
        if math.isinf(v):
            return "inf"
        return f"{v:.6f}"
    return str(v)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def write_csv(rows: list[dict]) -> None:
    order = {"empirical": 0, "empirical_pooled": 1, "analytic": 2}
    def key(r):
        return (r["drg_indegree"], -r["storage_frac_pct"],
                order.get(r["source"], 9), -(r["N_measured"] or 0))
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=key):
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# ---------------------------------------------------------------------------------------
# figure — (A) detection & eviction vs challenges c (δ_g=2);  (B) analytical vs empirical gap.
# ---------------------------------------------------------------------------------------
def make_plot(by_frac_pooled, by_frac_perN, delta_g) -> None:
    import numpy as np
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    # blue progression keyed by storage ρ%; 50% (escapes) muted grey, knee in strong blue.
    frac_shades = {50.0: "#b9b8b4", 33.0: "#9ec9f2", 30.0: "#6ba6e0",
                   25.0: "#2a78d6", 20.0: "#1a5bb0", 10.0: "#0b3a66"}
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))
    cs = np.arange(1, 51)

    # --- panel A: P_detect (solid) & P_evict (dashed, run-of-MAX_FAILS) vs challenges, per ρ ---
    ax = axes[0]
    for frac in sorted(by_frac_pooled, reverse=True):
        pf = by_frac_pooled[frac]
        col = frac_shades.get(frac, MUTED)
        ax.plot(cs, [p_detect(pf, int(c)) for c in cs], lw=1.8, color=col,
                label=f"keep {frac:g}% (p_fail={pf:.2f})")
        ax.plot(cs, [p_evict(pf, int(c)) for c in cs], lw=1.3, ls="--", color=col, alpha=0.9)
    ax.axhline(0.99, color=MUTED, lw=0.8, ls=":")
    ax.text(50, 0.995, " 0.99", fontsize=6.5, color=MUTED, va="bottom", ha="right")
    ax.set_xscale("log")
    ax.set_xticks([1, 5, 10, 20, 50])
    ax.set_xticklabels(["1", "5", "10", "20", "50"])
    ax.set_ylim(-0.03, 1.03)
    ax.set_xlabel("challenges c  (×5 s period ⇒ 1,5,10,20,50 → 5 s … 250 s wall-clock)")
    ax.set_ylabel("probability within c challenges")
    ax.set_title(f"Detection (—) vs eviction (– –, {MAX_FAILS} in a row), δ_g={delta_g}")
    ax.legend(frameon=False, fontsize=6.8, loc="center right", title="cheater storage")

    # --- panel B: analytical (coverage) vs empirical (time-gated) per-challenge p_fail + N band ---
    ax = axes[1]
    fracs = sorted(by_frac_pooled)                       # ascending ρ
    xs = np.array(fracs)
    pcov = np.array([1.0 - (f / 100.0) ** (1.0 + avg_indegree(delta_g)) for f in fracs])
    pfa = np.array([by_frac_pooled[f] for f in fracs])
    lo = np.array([min(by_frac_perN[f]) for f in fracs])
    hi = np.array([max(by_frac_perN[f]) for f in fracs])
    ax.plot(xs, pcov, lw=1.8, color="#8a1c5a", marker="s", ms=4,
            label="coverage  1−ρ^(1+δ̄)  (analytical upper bound)")
    ax.fill_between(xs, pfa, pcov, color="#8a1c5a", alpha=0.10)      # the over-optimism gap
    ax.fill_between(xs, lo, hi, color="#2a78d6", alpha=0.18, label="per-N band (2^18–2^22)")
    ax.plot(xs, pfa, lw=1.8, color="#2a78d6", marker="o", ms=5,
            label="time-gated  P(recompute>δ)  (empirical, pooled)")
    ax.set_xscale("log")
    ax.set_xticks(fracs)
    ax.set_xticklabels([f"{f:g}" for f in fracs])
    ax.invert_xaxis()                                   # less storage kept → right (easier to catch)
    ax.set_ylim(-0.03, 1.03)
    ax.set_xlabel("cheater storage kept ρ (% of labels)  →  less stored")
    ax.set_ylabel("per-challenge failure probability p_fail")
    ax.set_title(f"Coverage over-states detection (δ_g={delta_g}, δ={RESP_DELTA:g} s)")
    ax.legend(frameon=False, fontsize=6.8, loc="center left")
    ax.text(fracs[0], 0.08, "gap = cheap holes\n(recompute ≤ δ)", fontsize=6.5,
            color="#8a1c5a", ha="left")

    fig.suptitle("C3 — detection probability vs challenges per round (how many challenges catch a cheater)",
                 y=1.03, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
# self-test (deterministic; no Docker) — b2/b5/c2 lettered-check convention.
# ---------------------------------------------------------------------------------------
def _self_test() -> int:
    ok = True
    rng = random.Random(SEED)

    # (a) Markov p_evict vs the scalar no-run recurrence agree exactly
    worst = 0.0
    for p in (0.2, 0.5, 0.7, 0.95):
        for c in (5, 10, 20, 50):
            worst = max(worst, abs(p_evict(p, c) - (1.0 - _no_run_recurrence(p, c))))
    a_ok = worst < 1e-12
    ok &= a_ok
    print(f"  (a) Markov p_evict vs recurrence: max|Δ|={worst:.1e}  [{'ok' if a_ok else 'OFF'}]")

    # (b) p_evict vs seeded Monte-Carlo run-of-MAX_FAILS
    mc_worst = 0.0
    for p in (0.5, 0.7):
        for c in (10, 20):
            mc_worst = max(mc_worst, abs(p_evict(p, c) - _mc_evict(p, c, rng, 40000)))
    b_ok = mc_worst < 0.02
    ok &= b_ok
    print(f"  (b) p_evict vs Monte-Carlo: max|Δ|={mc_worst:.3f}  [{'ok' if b_ok else 'OFF'}]")

    # (c) coverage closed form == 1−ρ^3 at δ_g=2 (avg_indegree(2)=2.0 → exponent 3)
    exp = 1.0 + avg_indegree(HEADLINE_INDEGREE)
    c_ok = abs(exp - 3.0) < 1e-9 and abs((1 - 0.5 ** exp) - 0.875) < 1e-9 \
        and abs((1 - 0.25 ** exp) - 0.984375) < 1e-9
    ok &= c_ok
    print(f"  (c) coverage 1−ρ^{exp:.1f}: ρ=50%→{1-0.5**exp:.3f} ρ=25%→{1-0.25**exp:.3f}  "
          f"[{'ok' if c_ok else 'OFF'}]")

    # (d) monotonicity: P_detect ↑ in c and ↑ in (1−ρ) i.e. ↑ as p_fail grows
    det_c = [p_detect(0.6, c) for c in sorted(CHALLENGE_COUNTS)]
    det_p = [p_detect(p, 10) for p in (0.1, 0.3, 0.6, 0.9)]
    d_ok = all(x <= y + 1e-12 for x, y in zip(det_c, det_c[1:])) and \
           all(x <= y + 1e-12 for x, y in zip(det_p, det_p[1:]))
    ok &= d_ok
    print(f"  (d) P_detect↑ in c and in p_fail  [{'ok' if d_ok else 'OFF'}]")

    # (e) time-gated p_fail reduces to ≈0 at ρ=50% and ≈1 at ρ=10% (δ_g=2, small-N quick check)
    N = 1 << 18
    pk = bytes(random.Random(SEED ^ 0xC3).getrandbits(8) for _ in range(33))
    tab = parent_table(N, pk, HEADLINE_INDEGREE)
    idxs = [rng.randrange(1, N) for _ in range(400)]
    opened = build_opened(N, HEADLINE_INDEGREE, pk, idxs)
    ps = phi_star(RESP_DELTA)
    pf50 = sum(1 for x in sample_phis(N, pk, tab, opened, retained_mask(N, 0.50)) if x > ps) / len(idxs)
    pf10 = sum(1 for x in sample_phis(N, pk, tab, opened, retained_mask(N, 0.10)) if x > ps) / len(idxs)
    e_ok = pf50 < 0.05 and pf10 > 0.95
    ok &= e_ok
    print(f"  (e) time-gated p_fail: ρ=50%→{pf50:.2f} (≈0)  ρ=10%→{pf10:.2f} (≈1)  "
          f"φ*={ps:.4f}  [{'ok' if e_ok else 'OFF'}]")

    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# ---------------------------------------------------------------------------------------
def main() -> int:
    global RESP_DELTA
    ap = argparse.ArgumentParser(description="C3 detection vs challenges per round (issue #52).")
    ap.add_argument("--self-test", action="store_true", help="deterministic checks, no Docker")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--quick", action="store_true", help="drop N=2^22 for fast iteration")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--fractions", default=",".join(f"{f:g}" for f in FRACTIONS),
                    help="comma list of cheater label-storage %% kept")
    ap.add_argument("--indegrees", default=",".join(str(d) for d in INDEGREES),
                    help="comma list of DRG in-degrees δ_g")
    ap.add_argument("--ns", default=",".join(str(n.bit_length() - 1) for n in NS),
                    help="comma list of log2(N) measured sizes")
    ap.add_argument("--challenges", type=int, default=0,
                    help="override per-N challenge sample count (0 = size-adaptive default)")
    ap.add_argument("--delta", type=float, default=RESP_DELTA, help="response timeout δ (s)")
    args = ap.parse_args()

    if args.self_test:
        return _self_test()

    RESP_DELTA = args.delta
    fractions = [float(x) for x in args.fractions.split(",") if x]
    indegrees = [int(x) for x in args.indegrees.split(",") if x]
    ns = [1 << int(x) for x in args.ns.split(",") if x]
    if args.quick:
        ns = [n for n in ns if n <= (1 << 20)]
    ps = phi_star(RESP_DELTA)

    print(f"C3 detection vs challenges — seed={args.seed}, CHAIN_RATE={CHAIN_RATE/1e6:.2f} MH/s")
    print(f"  thesis N={REAL_PLOT_N:,}  δ={RESP_DELTA:g}s  φ*=δ·rate/N={ps:.6f}  "
          f"MAX_FAILS={MAX_FAILS}  period={CHALLENGE_PERIOD_S:g}s")
    print(f"  δ_g={indegrees}  ρ%={fractions}  N=2^{[n.bit_length()-1 for n in ns]}  c={CHALLENGE_COUNTS}")

    rows: list[dict] = []
    for delta_g in indegrees:
        exp = 1.0 + avg_indegree(delta_g)
        print(f"\n== δ_g={delta_g}  (coverage exponent 1+δ̄={exp:.2f}) ==")
        # per (δ_g, frac): collect per-N p_fail (band) + pooled phis (headline)
        perN: dict[float, list[float]] = {f: [] for f in fractions}
        pooled: dict[float, list[float]] = {f: [] for f in fractions}
        for N in ns:
            n_chal = args.challenges or CHALLENGES_BY_N.get(N, DEFAULT_CHALLENGES)
            rng = random.Random(args.seed ^ (0xC3 << 16) ^ (delta_g << 8) ^ (N.bit_length()))
            pk = bytes(rng.getrandbits(8) for _ in range(33))
            t0 = time.perf_counter()
            tab = parent_table(N, pk, delta_g)
            # paired sampling: ONE leaf set reused across all fractions at this (N, δ_g)
            idxs = [rng.randrange(1, N) for _ in range(n_chal)]
            opened = build_opened(N, delta_g, pk, idxs)
            for frac in fractions:
                phis = sample_phis(N, pk, tab, opened, retained_mask(N, frac / 100.0))
                pf = sum(1 for x in phis if x > ps) / len(phis)
                perN[frac].append(pf)
                pooled[frac].extend(phis)
                rows.append(metric_row("empirical", delta_g, frac, N, n_chal, phis,
                                        1.0 - (frac / 100.0) ** exp, ps, "time_gated",
                                        note="per-N point (band member)"))
            print(f"  N=2^{N.bit_length()-1:<2} ({n_chal} challenges, {time.perf_counter()-t0:4.1f}s): "
                  + "  ".join(f"ρ{f:g}%={perN[f][-1]:.2f}" for f in fractions))
            del tab

        # pooled headline row + analytic reference row, per fraction
        for frac in fractions:
            pcov = 1.0 - (frac / 100.0) ** exp
            rows.append(metric_row("empirical_pooled", delta_g, frac, 0, 0, pooled[frac],
                                    pcov, ps, "time_gated", note="pooled over measured N (headline)"))
            rows.append(metric_row("analytic", delta_g, frac, 0, 0, None,
                                    pcov, ps, "coverage",
                                    note="p_fail=coverage upper bound 1−ρ^(1+avg_indeg)"))

    write_csv(rows)

    if not args.no_plot:
        d_g = HEADLINE_INDEGREE if HEADLINE_INDEGREE in indegrees else indegrees[0]
        pooled_pf = {}
        perN_pf = {}
        for r in rows:
            if r["drg_indegree"] != d_g:
                continue
            if r["source"] == "empirical_pooled":
                pooled_pf[r["storage_frac_pct"]] = r["p_fail"]
            elif r["source"] == "empirical":
                perN_pf.setdefault(r["storage_frac_pct"], []).append(r["p_fail"])
        make_plot(pooled_pf, perN_pf, d_g)

    # ---- bottom line ----
    d_g = HEADLINE_INDEGREE if HEADLINE_INDEGREE in indegrees else indegrees[0]
    pooled_pf = {r["storage_frac_pct"]: r["p_fail"] for r in rows
                 if r["drg_indegree"] == d_g and r["source"] == "empirical_pooled"}
    print("\n" + "=" * 96)
    print(f"BOTTOM LINE (δ_g={d_g}, δ={RESP_DELTA:g}s, MAX_FAILS={MAX_FAILS}, ~{CHALLENGE_PERIOD_S:g}s/challenge):")
    for frac in sorted(pooled_pf, reverse=True):
        pf = pooled_pf[frac]
        d5 = p_detect(pf, 5)
        ev = e_first_run(pf)
        evs = "∞ (never)" if math.isinf(ev) else f"{ev:.1f} ch ≈ {ev*CHALLENGE_PERIOD_S:.0f}s"
        print(f"  keep {frac:4.0f}% labels: p_fail={pf:.2f} | P_detect(5)={d5:.3f} | "
              f"E[evict]={evs}")
    print("  Coverage (any opened hole = catch) is a strict UPPER BOUND; the gap is the cheater's cheap")
    print("  holes (back-cone ≤ δ), maximal at ρ=50%. Detection is recompute-time bound, not coverage-")
    print("  bound. A cheater below the ~50% threshold is caught by ONE challenge and evicted within")
    print(f"  {MAX_FAILS} rounds (~{MAX_FAILS*CHALLENGE_PERIOD_S:.0f}s); above it the cheater escapes but stored ~75% of the tree (C1).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
