#!/usr/bin/env python3
"""Issue #43 [B2] — Targeted chunk-majority capture / ID grinding (Phase 7, examiner point (ii)).

B2 answers: can an adversary capture a majority (>= ceil((s+1)/2) of s=3) of a target domain's
replicas, and what does it COST? Two questions, one deliverable:

  1. Can node IDs be GROUND?  node_id = SHA-256(pk) mod 2^160 is unsalted and the attacker picks
     its own pk (node/ids.py, node/pospace_admission.py), so it can brute-force pk until the id
     lands in a chosen ring arc. The ring is astronomically sparse (N << 2^160), so landing in
     one inter-node gap (width ~2^160/N) takes ~N hashes in expectation -- trivially cheap at
     every scale. The ONLY real cost is the PoSpace plot the winning pk must carry (one plot per
     admitted identity); PoSpace rate-limits the NUMBER of identities, not WHERE they land.
  2. Capture COST, random vs targeted.  Targeted placement co-locates ceil((s+1)/2)=2 ground
     identities on one chunk's consecutive replica slots -> captures ANY chosen chunk with a
     CONSTANT 2 plots (1 under B1's measured >=1-of-s vote weakness). Random placement, to capture
     a CHOSEN chunk, must corrupt ~O(N) identities (hypergeometric) -- useless for a target.

WHY A MICROBENCHMARK, NOT THE DOCKER TESTBED (mirrors A7): Docker cannot measure "hashes to grind
a pk" -- the cost is a pure, verifier-reproducible computation. B2 reuses the exact host-side ring
+ replica toolkit from experiments/b1_placement.py (the same converged-ring model the node, the
sims and B1 use) and node/ids.py, so every number is bit-for-bit reconstructible from (N, s, seed).
B1 already DEMONSTRATED targeted placement forging google.com at 100% on the live N=32 ring; B2
measures the COST of achieving that placement, and additionally proves the grind->admission->capture
chain end-to-end with a REAL in-process PoSpace ring (source=admission_inproc), the A7 pattern.

Three measured blocks + an honest control:
  * grind_scale / grind_target  -- hashes to land an id in a mean-gap (width 2^160/N) window, swept
    N in {32, 1e3, 1e6} empirically + 1e9 by the exact geometric expectation (validated at small N),
    in hashes and seconds (native-C floor at the 20.36 MH/s chainrate + measured Python).
  * capture_cost  -- identities (plots) needed: targeted (const 2 / 1) vs random (p in {.5,.9,.99}).
  * admission_inproc  -- grind a real pk, build its v3 plot, join() a real PoSpace ring, show it is
    admitted and becomes the target chunk's primary (and serves a forged value -> the B1 tie-in).
  * control  -- honest f=0 -> structural capture 0 (a protocol/design property: unsalted id=H(pk)
    + sparse ring, NOT chord.py reference-impl fragility).

New code in a new file (CLAUDE.md §2): imports/reads only. rpos/rpos.py, node/chord.py,
node/storage.py, node/ledger.py, node/pospace_admission.py, node/net.py, phase1/pospace_drg.py and
experiments/b1_placement.py stay byte-identical. Fixed seed 20260919.

Run:  python3 experiments/b2_grinding.py                 # full analysis -> CSV + PNG + stdout
      python3 experiments/b2_grinding.py --no-plot       # table only
      python3 experiments/b2_grinding.py --no-demo       # skip the in-process admission demo
      python3 experiments/b2_grinding.py --self-test     # deterministic checks, no Docker
      python3 experiments/b2_grinding.py --scale 32,1000 # quick grind-scale subset
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

REPO_ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
RESULTS = REPO_ROOT / "results"
OUT_CSV = RESULTS / "B2_targeted.csv"
OUT_FIG = RESULTS / "fig_B2_targeted.png"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# host-safe imports (hashlib / sim only -- NO dnspython, NO matplotlib at import time) ----------
from node.ids import node_id_from_pk, chunk_id, in_interval, RING_SIZE, RING_BITS  # noqa: E402
import b1_placement as b1                                                           # noqa: E402

# frozen B2 workload (PARAMETERS.md / run_b2.sh) -----------------------------------------------
SEED = 20260919                       # frozen repo seed (CLAUDE.md §2)
DEFAULT_N = 32                        # emulation ceiling (the real ring B2 grinds against)
DEFAULT_S = 3                         # replication factor
GRIND_PREFIX = b"b2-grind-"           # fixed -> verifier can re-run the exact search
SCALE_NS = [32, 1_000, 1_000_000, 1_000_000_000]   # ring sizes for the grind-cost sweep
EMPIRICAL_GRIND_CAP = 1_000_000       # largest N we actually grind (1e9 -> geometric expectation)
CAPTURE_NS = [32, 1_000, 1_000_000, 1_000_000_000]  # ring sizes for the capture-cost curve
CAPTURE_PROBS = [0.5, 0.9, 0.99]      # random-placement success targets
MAX_GRIND_FACTOR = 60                 # safety: give up a single grind after this * E[hashes]
DEMO_RING_N = 8                       # in-process PoSpace ring size (the A7 ring)
DEMO_PLOT_N = 1 << 10                 # test plot size (cheap; plot COST is quantified by A7)
FORGED_IP = "6.6.6.6"                 # the B1 forged A-record (tie-in)


# --- native single-core SHA-256 rate (shared convention with A7 / phase1/bench_v3) ------------
def _load_chain_rate(default_hs: float = 20_363_000.0) -> float:
    """hashes/s (native, single core) from phase1/results/chainrate.csv, matching A7/bench_v3."""
    p = REPO_ROOT / "phase1" / "results" / "chainrate.csv"
    if p.exists():
        for r in csv.reader(open(p)):
            if r and r[0] == "hashes_per_s_median":
                try:
                    return float(r[1])
                except ValueError:
                    pass
            if r and r[0] == "median":            # fallback: MH/s row
                try:
                    return float(r[1]) * 1e6
                except ValueError:
                    pass
    return default_hs
CHAIN_RATE = _load_chain_rate()


def _mean_sd(vals: list[float]) -> tuple[float, float]:
    vals = [v for v in vals if not math.isnan(v)]
    if not vals:
        return float("nan"), 0.0
    m = statistics.fmean(vals)
    sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
    return m, sd


# =============================================================================================
# Block 1 -- GRINDABILITY: hashes to land node_id = SHA-256(pk) in a chosen ring window.
# =============================================================================================
def grind_into_window(lo: int, hi: int, prefix: bytes,
                      max_hashes: int | None = None) -> tuple[bytes | None, int, int, float]:
    """Search pk = prefix || counter until node_id_from_pk(pk) lies in the OPEN arc (lo, hi).

    Returns (pk, found_id, hashes_tried, seconds). pk=None iff the budget max_hashes was hit.
    Deterministic given (lo, hi, prefix): the verifier re-runs the identical search.
    """
    c = 0
    t0 = time.perf_counter()
    while True:
        pk = prefix + c.to_bytes(12, "big")
        c += 1
        nid = node_id_from_pk(pk)
        if in_interval(nid, lo, hi, inc_left=False, inc_right=False):
            return pk, nid, c, time.perf_counter() - t0
        if max_hashes is not None and c >= max_hashes:
            return None, -1, c, time.perf_counter() - t0


def _window_at(center_frac: float, width: int) -> tuple[int, int]:
    """A width-`width` window placed at a deterministic ring position (fraction of the ring)."""
    lo = int(center_frac * RING_SIZE) % RING_SIZE
    hi = (lo + width) % RING_SIZE
    return lo, hi


def block1_grind_scale(ns: list[int], seed: int) -> list[dict]:
    """Hashes to land in a mean-gap window (width 2^160/N) vs ring size N.

    Empirical grind for N <= EMPIRICAL_GRIND_CAP; the exact geometric expectation E=2^160/width=N
    for larger N (validated against the measured points, CLAUDE.md "flag, don't hide"). Reports
    native-C-floor seconds (at CHAIN_RATE) and measured-Python seconds.
    """
    rng = random.Random(seed)
    rows: list[dict] = []
    py_hashes_total, py_secs_total = 0, 0.0          # to derive a Python hash-rate for extrapolation
    for N in ns:
        width = RING_SIZE // N                        # one mean inter-node gap
        e_hashes = RING_SIZE / width                  # == N (geometric mean)
        window_bits = width.bit_length() - 1
        if N <= EMPIRICAL_GRIND_CAP:
            reps = 8 if N <= 1_000 else (4 if N <= 100_000 else 2)
            hashes, secs = [], []
            for r in range(reps):
                lo, hi = _window_at(rng.random(), width)
                pk, nid, h, t = grind_into_window(
                    lo, hi, prefix=f"{GRIND_PREFIX.decode()}N{N}r{r}-".encode(),
                    max_hashes=int(MAX_GRIND_FACTOR * e_hashes) + 64)
                if pk is None:                        # astronomically unlikely; record the cap
                    h = int(MAX_GRIND_FACTOR * e_hashes)
                hashes.append(h); secs.append(t)
                py_hashes_total += h; py_secs_total += t
            h_m, h_sd = _mean_sd([float(x) for x in hashes])
            s_py_m, _ = _mean_sd(secs)
            source, note = "measured", f"empirical grind, {reps} reps, mean-gap window"
        else:
            h_m, h_sd, s_py_m = float("nan"), float("nan"), float("nan")
            source, note = "extrapolated", "geometric E[hashes]=2^160/gap=N; validated at N<=1e6"
        hashes_for_time = h_m if not math.isnan(h_m) else e_hashes
        rows.append({
            "metric": "grind_scale", "source": source, "strategy": "", "N": N, "s": "",
            "threshold": "", "window_bits": window_bits,
            "identities_needed": "", "hashes_expected": e_hashes, "hashes_measured": h_m,
            "seconds_native": hashes_for_time / CHAIN_RATE,
            "seconds_python": s_py_m, "capture_prob": "", "admitted": "", "note": note,
        })
    # derive a measured Python hash-rate and fill the extrapolated-N Python seconds
    py_rate = (py_hashes_total / py_secs_total) if py_secs_total > 0 else CHAIN_RATE
    for r in rows:
        if r["source"] == "extrapolated":
            r["seconds_python"] = r["hashes_expected"] / py_rate
            r["note"] += f"; python@{py_rate/1e6:.2f} MH/s"
    return rows, py_rate


def block1_grind_target(n: int, s: int, seed: int) -> list[dict]:
    """Concrete instance: grind the ceil((s+1)/2) ids that seize a real target chunk's first
    replica slots, over the actual N=32 emulation ring (b1_placement's auto-picked target)."""
    thresh = b1.capture_threshold(s)
    mal_idx, target = b1.targeted_indices(n, s, thresh, seed)   # the popular node-0-free chunk
    ring, _id2idx = b1.build_ring(n, s)
    key = chunk_id(target)
    primary = ring.successor_of(key)                            # current (honest) immediate succ
    gap = (primary - key) % RING_SIZE                           # width of the slot before `primary`
    window_bits = gap.bit_length() - 1
    e_each = RING_SIZE / gap
    # grind `thresh` DISTINCT ids into the open arc (key, primary): they become the first `thresh`
    # successors of the chunk, i.e. the capturing replica set.
    total_hashes, total_secs, got = 0, 0.0, []
    for k in range(thresh):
        pk, nid, h, t = grind_into_window(
            key, primary, prefix=f"b2-target-{k}-".encode(),
            max_hashes=int(MAX_GRIND_FACTOR * e_each) + 64)
        total_hashes += h; total_secs += t
        if pk is not None and nid not in got:
            got.append(nid)
    captured = len(got) >= thresh
    return [{
        "metric": "grind_target", "source": "real_ring", "strategy": "targeted", "N": n, "s": s,
        "threshold": thresh, "window_bits": window_bits, "identities_needed": thresh,
        "hashes_expected": thresh * e_each, "hashes_measured": float(total_hashes),
        "seconds_native": total_hashes / CHAIN_RATE, "seconds_python": total_secs,
        "capture_prob": 1.0 if captured else 0.0, "admitted": "",
        "note": f"grind {thresh} ids into (chunk,primary) of target={target!r}; "
                f"gap={window_bits} bits; captured={captured}",
    }]


# =============================================================================================
# Block 2 -- CAPTURE COST: identities (plots) needed, random vs targeted.
# =============================================================================================
def hyper_capture_prob(N: int, s: int, m: int, thresh: int) -> float:
    """P(>= thresh of a chunk's s consecutive replica slots are malicious | m of N nodes malicious,
    placed uniformly at random). Slot-centric hypergeometric: draw the s replica slots without
    replacement; P(exactly k malicious) = C(m,k) C(N-m, s-k) / C(N, s). Exact (math.comb), no scipy.
    """
    if m <= 0:
        return 0.0
    if m >= N:
        return 1.0 if thresh <= s else 0.0
    denom = math.comb(N, s)
    p = 0.0
    for k in range(thresh, s + 1):
        if k <= m and (s - k) <= (N - m):
            p += math.comb(m, k) * math.comb(N - m, s - k) / denom
    return p


def min_m_for_prob(N: int, s: int, thresh: int, p_target: float) -> int:
    """Smallest number of random malicious identities m s.t. P(capture a CHOSEN chunk) >= p_target.
    hyper_capture_prob is monotone increasing in m, so binary-search m in [thresh, N]."""
    lo, hi = thresh, N
    if hyper_capture_prob(N, s, hi, thresh) < p_target:
        return N                                     # unreachable even corrupting everyone
    while lo < hi:
        mid = (lo + hi) // 2
        if hyper_capture_prob(N, s, mid, thresh) >= p_target:
            hi = mid
        else:
            lo = mid + 1
    return lo


def block2_capture_cost(ns: list[int], s: int, probs: list[float]) -> list[dict]:
    thresh = b1.capture_threshold(s)                 # majority = ceil((s+1)/2)
    rows: list[dict] = []
    for N in ns:
        # targeted: a CONSTANT budget captures ANY chosen chunk (grind onto the consecutive slots)
        rows.append({
            "metric": "capture_cost", "source": "analytic", "strategy": "targeted_majority",
            "N": N, "s": s, "threshold": thresh, "window_bits": "", "identities_needed": thresh,
            "hashes_expected": "", "hashes_measured": "", "seconds_native": "", "seconds_python": "",
            "capture_prob": 1.0, "admitted": "", "note": "co-locate on consecutive replica slots",
        })
        rows.append({
            "metric": "capture_cost", "source": "analytic", "strategy": "targeted_effective",
            "N": N, "s": s, "threshold": 1, "window_bits": "", "identities_needed": 1,
            "hashes_expected": "", "hashes_measured": "", "seconds_native": "", "seconds_python": "",
            "capture_prob": 1.0, "admitted": "", "note": ">=1-of-s vote weakness (B1): 1 plot forges",
        })
        # random: m needed to capture a CHOSEN chunk with probability p
        for p in probs:
            m = min_m_for_prob(N, s, thresh, p)
            rows.append({
                "metric": "capture_cost", "source": "analytic", "strategy": f"random_p{int(p*100)}",
                "N": N, "s": s, "threshold": thresh, "window_bits": "", "identities_needed": m,
                "hashes_expected": "", "hashes_measured": "", "seconds_native": "",
                "seconds_python": "", "capture_prob": p, "admitted": "",
                "note": f"hypergeometric: smallest m with P(capture chosen chunk)>={p}",
            })
    return rows


# =============================================================================================
# Block 3 -- in-process admission demo: grind -> plot -> join a REAL PoSpace ring -> capture.
# =============================================================================================
def block3_admission_demo(seed: int) -> list[dict]:
    """Prove the grind->admission->capture chain on a real in-process PoSpace ring (A7 pattern).

    Lazily imports the node stack (dnspython): returns a skipped row if it is unavailable, so the
    cost analysis (Blocks 1-2) runs anywhere. Grinds a pk whose id lands immediately after a target
    chunk's key, joins the gated ring with a genuine v3 plot, and asserts it is admitted and becomes
    the chunk's primary (and serves the forged value -> ties to B1).
    """
    try:
        import asyncio
        from node.net import Network
        from node.pospace_admission import PoSpaceNode
        from node.run_node import _pk_for
    except Exception as e:                                           # dnspython / env missing
        return [{
            "metric": "admission_demo", "source": "admission_inproc", "strategy": "targeted",
            "N": DEMO_RING_N, "s": DEFAULT_S, "threshold": 1, "window_bits": "",
            "identities_needed": "", "hashes_expected": "", "hashes_measured": "",
            "seconds_native": "", "seconds_python": "", "capture_prob": "", "admitted": "skipped",
            "note": f"in-process demo skipped (import failed: {type(e).__name__}); "
                    f"run under the 3.11 env with dnspython",
        }]

    async def _converge(nodes, rounds: int) -> None:
        for _ in range(rounds):
            for nd in nodes:
                if nd.alive:
                    await nd.stabilize()
            for nd in nodes:
                if nd.alive:
                    await nd.fix_fingers()
                    await nd.check_predecessor()
            await asyncio.sleep(0)

    def _live_primary(ids: list[int], key: int) -> int:
        nxt = [i for i in sorted(ids) if i > key]
        return nxt[0] if nxt else min(ids)

    async def _run() -> dict:
        net = Network()
        nodes = [PoSpaceNode(_pk_for(j), net, plot_n=DEMO_PLOT_N, seed=seed)
                 for j in range(DEMO_RING_N)]
        await nodes[0].create()
        for nd in nodes[1:]:
            await nd.join(nodes[0].node_id)
            await _converge(nodes, rounds=6)
        honest_ids = [nd.node_id for nd in nodes]

        # pick a target domain whose honest primary is NOT node 0 (keep the anchor honest),
        # then grind a malicious id into the open gap (chunk_key, honest_primary).
        domains = b1.load_served_domains()
        target, key, primary = None, None, None
        for d in domains:
            k = chunk_id(d)
            p = _live_primary(honest_ids, k)
            if p != nodes[0].node_id:
                target, key, primary = d, k, p
                break
        if target is None:                       # fall back to the most popular domain
            target = domains[0]; key = chunk_id(target); primary = _live_primary(honest_ids, key)

        mal_pk, mal_id, hashes, _t = grind_into_window(
            key, primary, prefix=b"b2-demo-mal-", max_hashes=10_000_000)
        assert mal_pk is not None, "grind failed in demo (unexpected at N=8)"

        mal = PoSpaceNode(mal_pk, net, plot_n=DEMO_PLOT_N, seed=seed)
        admitted = True
        try:
            await mal.join(nodes[0].node_id)     # real gated admission (builds plot + passes challenge)
        except Exception:
            admitted = False
        await _converge(nodes + [mal], rounds=8)

        # it should now be the chunk's primary (immediate successor of the key)
        live_ids = honest_ids + [mal.node_id]
        becomes_primary = (_live_primary(live_ids, key) == mal.node_id)
        routed, _h = await mal.find_successor(key)
        routed_ok = (routed == mal.node_id)

        # tie-in to B1: the captured primary serves a forged value, read back via an honest reader
        forged_served = False
        try:
            await mal.store_chunk(target, FORGED_IP)
            val, _vote, _hops = await nodes[0].get_chunk(target)
            forged_served = (val == FORGED_IP)
        except Exception:
            pass

        for nd in nodes + [mal]:
            nd.stop()
        return {
            "admitted": admitted, "becomes_primary": becomes_primary and routed_ok,
            "hashes": hashes, "target": target, "forged_served": forged_served,
            "mal_id": mal_id, "primary": primary,
        }

    res = asyncio.run(_run())
    ok = res["admitted"] and res["becomes_primary"]
    return [{
        "metric": "admission_demo", "source": "admission_inproc", "strategy": "targeted",
        "N": DEMO_RING_N, "s": DEFAULT_S, "threshold": 1, "window_bits": "",
        "identities_needed": 1, "hashes_expected": float(DEMO_RING_N),
        "hashes_measured": float(res["hashes"]), "seconds_native": res["hashes"] / CHAIN_RATE,
        "seconds_python": "", "capture_prob": 1.0 if res["forged_served"] else "",
        "admitted": "yes" if ok else "no",
        "note": f"grinded pk admitted (real v3 plot+challenge) & became primary of "
                f"target={res['target']!r}; forged_served={res['forged_served']}",
    }]


# =============================================================================================
# Control -- honest f=0 placement captures nothing (adversary-caused, not chord.py fragility).
# =============================================================================================
def control_row(n: int, s: int) -> list[dict]:
    frac = b1.structural_capture_fraction([], n, s)          # no malicious nodes
    return [{
        "metric": "control", "source": "real_ring", "strategy": "honest", "N": n, "s": s,
        "threshold": b1.capture_threshold(s), "window_bits": "", "identities_needed": 0,
        "hashes_expected": "", "hashes_measured": "", "seconds_native": "", "seconds_python": "",
        "capture_prob": frac, "admitted": "",
        "note": "f=0 honest control: structural capture over all served chunks",
    }]


# =============================================================================================
# CSV.
# =============================================================================================
FIELDS = ["metric", "source", "strategy", "N", "s", "threshold", "window_bits",
          "identities_needed", "hashes_expected", "hashes_measured",
          "seconds_native", "seconds_python", "capture_prob", "admitted", "note"]

_METRIC_ORDER = {"grind_scale": 0, "grind_target": 1, "capture_cost": 2,
                 "admission_demo": 3, "control": 4}


def _fmt(v) -> str:
    if isinstance(v, float):
        if math.isnan(v):
            return ""
        if abs(v) >= 1e6 or (v != 0 and abs(v) < 1e-3):
            return f"{v:.6g}"
        return f"{v:.4f}"
    return str(v)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def write_csv(rows: list[dict]) -> None:
    def key(r):
        n = r.get("N", 0)
        n = n if isinstance(n, int) else 0
        return (_METRIC_ORDER.get(r["metric"], 9), n, str(r.get("strategy", "")))
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=key):
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# =============================================================================================
# Figure: (1) grind cost vs N (log-log, O(N) line + measured points, thesis & 1e9 annotated);
# (2) plotted-identities-to-capture-a-CHOSEN-chunk vs N: targeted (const) vs random (p50/90/99).
# Style mirrors A7/A4/A5.
# =============================================================================================
def make_plot(rows: list[dict]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    EXPC, MEASC, TARGC, TEFFC = "#2a78d6", "#8a1c5a", "#1baf7a", "#e08a1e"
    RANDC = {50: "#9ec9f2", 90: "#2a78d6", 99: "#0b3a66"}
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    # --- panel 1: grind cost (hashes) vs N ---
    ax = axes[0]
    gs = sorted((r for r in rows if r["metric"] == "grind_scale"), key=lambda r: r["N"])
    xs = [r["N"] for r in gs]
    y_exp = [r["hashes_expected"] for r in gs]
    meas = [(r["N"], r["hashes_measured"]) for r in gs
            if isinstance(r["hashes_measured"], float) and not math.isnan(r["hashes_measured"])]
    ax.plot(xs, y_exp, lw=1.8, ls="--", color=EXPC, label="E[hashes] = N  (geometric)")
    if meas:
        ax.plot([m[0] for m in meas], [m[1] for m in meas], marker="o", ms=6, lw=0,
                color=MEASC, label="measured grind")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("ring size N (nodes)"); ax.set_ylabel("hashes to land in one gap")
    ax.set_title("Grinding cost to hit a chosen position")
    # annotate a seconds axis note at the 1e9 point
    big = [r for r in gs if r["N"] == max(xs)]
    if big:
        sN = big[0]["seconds_native"]
        ax.annotate(f"N=1e9: ~{sN:.0f}s (native)\n= trivially cheap",
                    xy=(max(xs), big[0]["hashes_expected"]),
                    xytext=(0.30, 0.82), textcoords="axes fraction", fontsize=8,
                    color=MUTED, arrowprops=dict(arrowstyle="->", color=MUTED, lw=0.8))
    ax.legend(frameon=False, fontsize=8, loc="lower right")

    # --- panel 2: identities (plots) to capture a CHOSEN chunk vs N ---
    ax = axes[1]
    cc = [r for r in rows if r["metric"] == "capture_cost"]
    cap_ns = sorted({r["N"] for r in cc})

    def _series(strategy):
        out = {r["N"]: r["identities_needed"] for r in cc if r["strategy"] == strategy}
        return [out.get(n, float("nan")) for n in cap_ns]

    ax.plot(cap_ns, _series("targeted_majority"), marker="s", ms=6, lw=1.9, color=TARGC,
            label="targeted (majority) = 2 plots")
    ax.plot(cap_ns, _series("targeted_effective"), marker="D", ms=5, lw=1.5, ls="--", color=TEFFC,
            label="targeted (>=1-of-s, B1) = 1 plot")
    for p in (50, 90, 99):
        ax.plot(cap_ns, _series(f"random_p{p}"), marker="o", ms=5, lw=1.6, color=RANDC[p],
                label=f"random, capture @ {p}%")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("ring size N (nodes)"); ax.set_ylabel("plotted identities to capture a chosen chunk")
    ax.set_title("Capture cost: targeted O(1) vs random O(N)")
    ax.legend(frameon=False, fontsize=8, loc="upper left")

    fig.suptitle("B2 — targeted chunk-majority capture: ID grinding is cheap; "
                 "PoSpace limits identity count, not placement", y=1.03, fontsize=11)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# =============================================================================================
# Self-test -- deterministic, no Docker (the plan's verification step).
# =============================================================================================
def _self_test() -> int:
    ok = True
    n, s = DEFAULT_N, DEFAULT_S
    thresh = b1.capture_threshold(s)
    print(f"[self-test] N={n} s={s} thresh={thresh} CHAIN_RATE={CHAIN_RATE/1e6:.2f} MH/s")

    # (a) grinding lands in a target window within a sane budget, and measured ~ geometric E.
    hs = []
    for r in range(12):
        width = RING_SIZE // 50                       # ~50-node ring gap
        lo, hi = _window_at(random.Random(SEED + r).random(), width)
        pk, nid, h, _t = grind_into_window(lo, hi, prefix=f"st-{r}-".encode(),
                                           max_hashes=60 * 50 + 64)
        assert pk is not None and in_interval(nid, lo, hi), f"grind missed window r={r}"
        hs.append(h)
    mean_h = statistics.fmean(hs)
    a_ok = 50 / 4 <= mean_h <= 50 * 4                  # geometric mean ~ 50; generous band
    ok &= a_ok
    print(f"  (a) grind mean hashes={mean_h:.1f} (expect ~50)  [{'ok' if a_ok else 'OFF'}]")

    # (b) targeted threshold captures the chunk: 2 ground ids on the first 2 successor slots.
    tgt_rows = block1_grind_target(n, s, SEED)
    b_ok = tgt_rows[0]["capture_prob"] == 1.0 and tgt_rows[0]["identities_needed"] == thresh
    ok &= b_ok
    print(f"  (b) targeted grind captured={tgt_rows[0]['capture_prob']==1.0} "
          f"ids={tgt_rows[0]['identities_needed']}  [{'ok' if b_ok else 'OFF'}]")

    # (c) hypergeometric closed-form matches a Monte-Carlo estimate.
    N_mc, m_mc = 32, 10
    exact = hyper_capture_prob(N_mc, s, m_mc, thresh)
    rng = random.Random(SEED)
    trials, hit = 20000, 0
    pool = list(range(N_mc))
    for _ in range(trials):
        mal = set(rng.sample(pool, m_mc))
        slots = rng.sample(pool, s)                   # s consecutive slots ~ s random distinct nodes
        if sum(1 for x in slots if x in mal) >= thresh:
            hit += 1
    mc = hit / trials
    c_ok = abs(exact - mc) <= 0.02
    ok &= c_ok
    print(f"  (c) hypergeometric exact={exact:.4f} MC={mc:.4f}  [{'ok' if c_ok else 'OFF'}]")

    # (d) honest control: f=0 -> structural capture 0.
    d_frac = b1.structural_capture_fraction([], n, s)
    d_ok = d_frac == 0.0
    ok &= d_ok
    print(f"  (d) honest control capture fraction={d_frac:.4f}  [{'ok' if d_ok else 'OFF'}]")

    # (e) min_m monotonicity + sanity: random needs O(N) plots, targeted constant.
    m50 = min_m_for_prob(n, s, thresh, 0.5)
    e_ok = m50 >= 2 * thresh and hyper_capture_prob(n, s, m50, thresh) >= 0.5
    ok &= e_ok
    print(f"  (e) random m@50%={m50} vs targeted={thresh}  [{'ok' if e_ok else 'OFF'}]")

    # (f) in-process admission demo (skips cleanly if dnspython absent).
    demo = block3_admission_demo(SEED)[0]
    if demo["admitted"] == "skipped":
        print(f"  (f) admission demo SKIPPED ({demo['note'].split('(')[-1]}")
    else:
        f_ok = demo["admitted"] == "yes"
        ok &= f_ok
        print(f"  (f) grinded node admitted & primary={demo['admitted']} "
              f"forged_served={'forged_served=True' in demo['note']}  [{'ok' if f_ok else 'OFF'}]")

    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# =============================================================================================
def main() -> int:
    ap = argparse.ArgumentParser(description="B2 targeted capture / ID grinding (issue #43).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--no-demo", action="store_true", help="skip the in-process admission demo")
    ap.add_argument("--self-test", action="store_true", help="deterministic checks, no Docker")
    ap.add_argument("--scale", default=",".join(str(x) for x in SCALE_NS),
                    help="comma list of ring sizes N for the grind-cost sweep")
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()

    if args.self_test:
        return _self_test()

    scale_ns = [int(x) for x in args.scale.split(",") if x]
    print(f"B2 grinding / capture-cost analysis — seed={args.seed}, "
          f"CHAIN_RATE={CHAIN_RATE/1e6:.2f} MH/s, N={DEFAULT_N} s={DEFAULT_S}")

    rows: list[dict] = []
    print("\n== Block 1: grindability (hashes to hit a chosen position) ==")
    scale_rows, py_rate = block1_grind_scale(scale_ns, args.seed)
    rows += scale_rows
    for r in scale_rows:
        hm = r["hashes_measured"]
        hm_s = f"{hm:,.0f}" if isinstance(hm, float) and not math.isnan(hm) else "(extrapolated)"
        print(f"  N={r['N']:>12,}  gap=2^{r['window_bits']}  E[hashes]={r['hashes_expected']:,.0f}  "
              f"measured={hm_s}  native={r['seconds_native']*1e3:.3f} ms")
    tgt_rows = block1_grind_target(DEFAULT_N, DEFAULT_S, args.seed)
    rows += tgt_rows
    t = tgt_rows[0]
    print(f"  TARGET: {t['note']}  hashes={t['hashes_measured']:,.0f}  native={t['seconds_native']*1e3:.3f} ms")

    print("\n== Block 2: capture cost (plotted identities for a CHOSEN chunk) ==")
    cap_rows = block2_capture_cost(CAPTURE_NS, DEFAULT_S, CAPTURE_PROBS)
    rows += cap_rows
    for N in CAPTURE_NS:
        sub = {r["strategy"]: r["identities_needed"] for r in cap_rows if r["N"] == N}
        print(f"  N={N:>12,}  targeted(maj)={sub['targeted_majority']}  "
              f"targeted(eff)={sub['targeted_effective']}  "
              f"random@50%={sub['random_p50']}  @90%={sub['random_p90']}  @99%={sub['random_p99']}")

    if not args.no_demo:
        print("\n== Block 3: in-process admission demo (grind -> plot -> join -> capture) ==")
        demo_rows = block3_admission_demo(args.seed)
        rows += demo_rows
        print(f"  {demo_rows[0]['admitted']}: {demo_rows[0]['note']}")

    rows += control_row(DEFAULT_N, DEFAULT_S)
    print(f"\n== Control: honest f=0 structural capture = "
          f"{rows[-1]['capture_prob']:.4f} ==")

    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
