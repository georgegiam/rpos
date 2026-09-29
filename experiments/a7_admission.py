#!/usr/bin/env python3
"""Issue #38 [A7] — Admission: join time vs plot size (Phase 6, examiner point (iii)).

A7 answers "how expensive is it to join the ring, and how does that cost scale with the PoSpace
plot size?" — the admission cost the thesis never measured (it only measured plot initialisation
in isolation). It holds the ring at N=8 and sweeps the plot size over {2^10, 2^12, 2^14, 2^16}
(the frozen v3 DRG scheme, phase1/pospace_drg.py), δ=2 (the node default) as the headline plus a
δ∈{2,4,8} in-degree secondary axis.

WHY A MICROBENCHMARK, NOT THE DOCKER TESTBED (see the plan / A7_NOTES.md): at these sizes a plot
takes ~1.8 ms (2^10) → ~114 ms (2^16) at δ=2, so a real N=8 container ring would bury that
~110 ms plot-size signal under seconds of container-startup / ring-convergence noise. A7 instead
measures the node's EXACT admission code, deterministically and with a fixed seed, two ways:

  * source=component — directly time the very functions the node runs on admission
    (node/pospace_admission.py::_build_plot -> plot_v3 + commit_v3; the successor challenge ->
    prove_v3 + verify_v3), imported the same way the node imports them, over the 8 REAL ring keys
    (_pk_for(0..7)) × repeats. This gives the plot / commit / challenge DECOMPOSITION the issue
    asks for, plus derived labels/s, plot bytes, proof bytes, and a native-rate "optimised C
    plotter" floor (bench_v3's CHAIN_RATE convention).
  * source=ring_inproc — build a REAL in-process 8-node ring of the actual PoSpaceNode over
    node/net.py and time each node's genuine create()/join() (build plot -> find_successor ->
    successor challenge -> verify -> admit). In-process bus ⇒ ~zero network, so this is a lower
    bound on socket admission (over real sockets add ~a couple RPC RTTs; δ=2 s timeout per
    PARAMETERS.md). It cross-checks the component sum against the real admission path.

Reuses phase1/pospace_drg.py (imported via node/pospace_admission.py, never copied — CLAUDE.md §2)
and phase1/results/chainrate.csv. Touches no frozen artifact. Fixed seed 20260919.

Run:  python3 experiments/a7_admission.py                       # full sweep -> CSV + PNG + stdout
      python3 experiments/a7_admission.py --no-plot             # table only
      python3 experiments/a7_admission.py --component-only      # skip the in-process ring
      python3 experiments/a7_admission.py --sizes 1024,4096 --repeats 1   # quick smoke
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import math
import random
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
OUT_CSV = RESULTS / "A7_admission.csv"
OUT_FIG = RESULTS / "fig_A7_admission.png"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# import the v3 DRG admission functions THE SAME WAY THE NODE DOES: node/pospace_admission.py
# re-exports them from phase1/pospace_drg.py and puts phase1/ on sys.path as a side effect, so the
# sibling `drg` module (for the native-rate floor) is importable afterwards.
from node.pospace_admission import (  # noqa: E402
    plot_v3, commit_v3, prove_v3, verify_v3, PoSpaceNode,
    PLOT_N as NODE_DEFAULT_PLOT_N, DRG_INDEGREE as NODE_DEFAULT_DELTA,
    CHALLENGE_TIMEOUT,
)
from node.net import Network            # noqa: E402
from node.ids import node_id_from_pk    # noqa: E402
from node.run_node import _pk_for       # noqa: E402  (deterministic ring identities)
from drg import parents_all             # noqa: E402  (phase1, on sys.path via the import above)

# frozen A7 workload (PARAMETERS.md / run_a7.sh) — recorded per row for a self-contained deliverable
A7_SIZES = [1 << 10, 1 << 12, 1 << 14, 1 << 16]   # plot leaves; issue #38
A7_DELTAS = [2, 4, 8]                              # DRG in-degree; 2 = node default = headline
A7_RING_N = 8                                      # "at N=8"
A7_REPEATS = 5                                     # per (key,size,delta) for mean±sd stability
A7_CHALLENGES = 30                                 # prove/verify calls averaged per (key,repeat)
SEED = 20260919                                    # frozen repo seed (CLAUDE.md §2)

# --- native single-core SHA-256 rate (shared convention with phase1/bench_v3.py) ---
PK_BYTES = 33
LABEL_FIXED = PK_BYTES + 8                          # pk(33) || i(8) before the parent labels
CHAIN_INPUT_BYTES = 32 + PK_BYTES + 8              # the v2 chain hash bench_v3's CHAIN_RATE times
def _sha_blocks(nbytes: int) -> int:               # SHA-256 compression blocks for an nbyte message
    return (nbytes + 9 + 63) // 64
BLOCKS_CHAIN = _sha_blocks(CHAIN_INPUT_BYTES)


def _load_chain_rate(default_hs: float = 20_363_000.0) -> float:
    """hashes/s (native, single core) from phase1/results/chainrate.csv, matching bench_v3."""
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


# ---- percentile / stats helpers — identical to experiments/a5_updates.py / a4_replication.py ----
def _mean_sd(vals: list[float]) -> tuple[float, float]:
    vals = [v for v in vals if not math.isnan(v)]
    if not vals:
        return float("nan"), 0.0
    m = statistics.fmean(vals)
    sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
    return m, sd


# ---------------------------------------------------------------------------------------
# source = component: time the exact node-imported admission functions.
# ---------------------------------------------------------------------------------------
def _native_floor_ms(pk: bytes, N: int, delta: int) -> float:
    """Optimised-C plot-time floor: N label-hashes at the native SHA rate, weighted by the mean
    number of SHA blocks per v3 label (each label hashes pk||i||parent-labels). Mirrors bench_v3."""
    P = parents_all(N, pk, delta)
    mean_blocks = sum(_sha_blocks(LABEL_FIXED + len(p) * 32) for p in P) / N
    return N * (mean_blocks / BLOCKS_CHAIN) / CHAIN_RATE * 1e3


def component_row(N: int, delta: int, repeats: int, challenges: int) -> dict:
    """Time plot_v3 / commit_v3 / prove_v3 / verify_v3 over the 8 ring keys × repeats."""
    t_plot, t_commit, t_prove, t_verify, t_admit = [], [], [], [], []
    proof_bytes_seen: list[int] = []
    for j in range(A7_RING_N):
        pk = _pk_for(j)
        # per-node challenge RNG mirrors node/pospace_admission.py:68 (seed ^ node_id)
        rng = random.Random(SEED ^ (node_id_from_pk(pk) & ((1 << 64) - 1)))
        for _ in range(repeats):
            t0 = time.perf_counter(); labels = plot_v3(pk, N, delta)
            tp = time.perf_counter() - t0

            t0 = time.perf_counter(); levels, root = commit_v3(labels)
            tc = time.perf_counter() - t0

            prove_s, verify_s = [], []
            for _c in range(challenges):
                i = rng.randrange(1, N)
                t0 = time.perf_counter(); proof = prove_v3(levels, pk, N, delta, i)
                prove_s.append(time.perf_counter() - t0)
                t0 = time.perf_counter(); ok = verify_v3(root, pk, N, delta, i, proof)
                verify_s.append(time.perf_counter() - t0)
                assert ok, f"verify_v3 failed at N={N} delta={delta} i={i}"
                proof_bytes_seen.append(sum(len(lbl) + 32 * len(path)
                                            for (lbl, path) in proof.values()))
            mp = statistics.fmean(prove_s)
            mv = statistics.fmean(verify_s)
            t_plot.append(tp); t_commit.append(tc); t_prove.append(mp); t_verify.append(mv)
            t_admit.append(tp + tc + mp + mv)     # one challenge = the join gate

    plot_m, plot_sd = _mean_sd([x * 1e3 for x in t_plot])
    commit_m, commit_sd = _mean_sd([x * 1e3 for x in t_commit])
    prove_m, _ = _mean_sd([x * 1e3 for x in t_prove])
    verify_m, _ = _mean_sd([x * 1e3 for x in t_verify])
    admit_m, admit_sd = _mean_sd([x * 1e3 for x in t_admit])
    labels_per_s = N / (plot_m / 1e3) if plot_m > 0 else float("nan")
    return {
        "source": "component", "delta": delta, "log2_size": N.bit_length() - 1, "size": N,
        "ring_n": A7_RING_N, "repeats": repeats,
        "t_plot_ms": plot_m, "t_plot_sd": plot_sd,
        "t_commit_ms": commit_m, "t_commit_sd": commit_sd,
        "t_prove_ms": prove_m, "t_verify_ms": verify_m,
        "t_admission_ms": admit_m, "t_admission_sd": admit_sd,
        "labels_per_s": labels_per_s, "plot_bytes": 32 * N,
        "proof_bytes": float(statistics.median(proof_bytes_seen)) if proof_bytes_seen else float("nan"),
        "plot_native_floor_ms": _native_floor_ms(_pk_for(0), N, delta),
        "note": "plot+commit+prove+verify, measured over 8 ring keys; +~2 RPC RTT over sockets",
    }


# ---------------------------------------------------------------------------------------
# source = ring_inproc: a REAL in-process 8-node ring; time the genuine create()/join().
# ---------------------------------------------------------------------------------------
async def _converge(nodes, rounds: int) -> None:
    """stabilize + fix_fingers + check_predecessor rounds (mirrors node/tests/util.run_protocol)."""
    for _ in range(rounds):
        for nd in nodes:
            if nd.alive:
                await nd.stabilize()
        for nd in nodes:
            if nd.alive:
                await nd.fix_fingers()
                await nd.check_predecessor()
        await asyncio.sleep(0)


async def _time_one_ring(N: int, delta: int) -> tuple[float, list[float]]:
    """Build one 8-node ring; return (founder create ms, [joiner admission ms])."""
    net = Network()
    nodes = [PoSpaceNode(_pk_for(j), net, plot_n=N, drg_indegree=delta, seed=SEED)
             for j in range(A7_RING_N)]
    t0 = time.perf_counter(); await nodes[0].create()          # founder: build plot, no challenge
    create_ms = (time.perf_counter() - t0) * 1e3
    joins: list[float] = []
    for nd in nodes[1:]:
        t0 = time.perf_counter(); await nd.join(nodes[0].node_id)  # real gated admission
        joins.append((time.perf_counter() - t0) * 1e3)
        await _converge(nodes, rounds=6)                       # NOT timed — isolate admission
    for nd in nodes:                                           # tidy up the event-loop tasks
        nd.stop()
    return create_ms, joins


def ring_row(N: int, delta: int, repeats: int) -> dict:
    creates, joins = [], []
    for _ in range(repeats):
        c, js = asyncio.run(_time_one_ring(N, delta))
        creates.append(c); joins.extend(js)
    join_m, join_sd = _mean_sd(joins)
    create_m, _ = _mean_sd(creates)
    return {
        "source": "ring_inproc", "delta": delta, "log2_size": N.bit_length() - 1, "size": N,
        "ring_n": A7_RING_N, "repeats": repeats,
        "t_plot_ms": float("nan"), "t_plot_sd": float("nan"),
        "t_commit_ms": float("nan"), "t_commit_sd": float("nan"),
        "t_prove_ms": float("nan"), "t_verify_ms": float("nan"),
        "t_admission_ms": join_m, "t_admission_sd": join_sd,
        "labels_per_s": float("nan"), "plot_bytes": 32 * N,
        "proof_bytes": float("nan"), "plot_native_floor_ms": float("nan"),
        "note": f"real join() incl challenge over in-process bus (~0 net); founder create={create_m:.1f} ms",
    }


# ---------------------------------------------------------------------------------------
# CSV.
# ---------------------------------------------------------------------------------------
FIELDS = ["source", "delta", "log2_size", "size", "ring_n", "repeats",
          "t_plot_ms", "t_plot_sd", "t_commit_ms", "t_commit_sd",
          "t_prove_ms", "t_verify_ms", "t_admission_ms", "t_admission_sd",
          "labels_per_s", "plot_bytes", "proof_bytes", "plot_native_floor_ms", "note"]


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
    def key(r):    # component first, then ring; then δ, then size
        return (0 if r["source"] == "component" else 1, r["delta"], r["size"])
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=key):
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# ---------------------------------------------------------------------------------------
# Plot: (1) join time vs plot size at δ=2 (log-log), plot/commit/admission + native floor +
# in-process ring cross-check; (2) plot time vs plot size for δ∈{2,4,8} (in-degree cost).
# Style mirrors A2/A3/A4/A5.
# ---------------------------------------------------------------------------------------
def make_plot(rows: list[dict]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    PLOTC, COMMITC, ADMITC, RINGC, NATIVEC = "#2a78d6", "#e08a1e", "#0b0b0b", "#8a1c5a", "#1baf7a"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    def series(source, delta, field):
        rs = sorted((r for r in rows if r["source"] == source and r["delta"] == delta),
                    key=lambda r: r["size"])
        xs = [r["size"] for r in rs]
        ys = [r[field] for r in rs]
        return xs, ys

    # --- panel 1: join time vs plot size at δ=2 ---
    ax = axes[0]
    d = A7_DELTAS[0]
    xs, y_plot = series("component", d, "t_plot_ms")
    _, y_commit = series("component", d, "t_commit_ms")
    _, y_admit = series("component", d, "t_admission_ms")
    _, y_native = series("component", d, "plot_native_floor_ms")
    ax.plot(xs, y_admit, marker="o", ms=5, lw=1.9, color=ADMITC, label="admission total (measured)")
    ax.plot(xs, y_plot, marker="s", ms=4, lw=1.6, color=PLOTC, label="plot generation")
    ax.plot(xs, y_commit, marker="^", ms=4, lw=1.6, color=COMMITC, label="Merkle commit")
    ax.plot(xs, y_native, marker="", lw=1.4, ls=":", color=NATIVEC, label="plot native floor (C)")
    xr, yr = series("ring_inproc", d, "t_admission_ms")
    if xr and not all(math.isnan(v) for v in yr):
        ax.plot(xr, yr, marker="D", ms=4, lw=1.4, ls="--", color=RINGC,
                label="in-process ring join()")
    ax.set_xscale("log", base=2); ax.set_yscale("log")
    ax.set_xlabel("plot size (leaves)"); ax.set_ylabel("time (ms)")
    ax.set_title(f"Join time vs plot size (N={A7_RING_N}, δ={d})")
    ax.legend(frameon=False, fontsize=8, loc="upper left")

    # --- panel 2: plot generation time vs size for δ∈{2,4,8} (in-degree cost) ---
    ax = axes[1]
    shades = {2: "#9ec9f2", 4: "#2a78d6", 8: "#0b3a66"}
    for delta in A7_DELTAS:
        xs, yp = series("component", delta, "t_plot_ms")
        if xs:
            ax.plot(xs, yp, marker="o", ms=4, lw=1.7, color=shades.get(delta, PLOTC),
                    label=f"δ={delta}")
    ax.set_xscale("log", base=2); ax.set_yscale("log")
    ax.set_xlabel("plot size (leaves)"); ax.set_ylabel("plot generation time (ms)")
    ax.set_title("Plot cost vs DRG in-degree δ")
    ax.legend(frameon=False, fontsize=9, title="in-degree")

    fig.suptitle("A7 — admission (join) time vs PoSpace plot size", y=1.03, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# ---------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="A7 admission join-time vs plot-size (issue #38).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--component-only", action="store_true",
                    help="skip the in-process ring cross-check (faster)")
    ap.add_argument("--sizes", default=",".join(str(s) for s in A7_SIZES),
                    help="comma list of plot sizes (powers of two)")
    ap.add_argument("--deltas", default=",".join(str(d) for d in A7_DELTAS),
                    help="comma list of DRG in-degrees")
    ap.add_argument("--repeats", type=int, default=A7_REPEATS,
                    help="repeats per (key,size,delta) for error bars")
    ap.add_argument("--challenges", type=int, default=A7_CHALLENGES,
                    help="prove/verify calls averaged per (key,repeat)")
    args = ap.parse_args()

    sizes = [int(s) for s in args.sizes.split(",") if s]
    deltas = [int(d) for d in args.deltas.split(",") if d]
    for N in sizes:
        assert N > 1 and (N & (N - 1)) == 0, f"plot size {N} must be a power of two"

    print(f"A7 admission microbenchmark — N_ring={A7_RING_N}, seed={SEED}, "
          f"CHAIN_RATE={CHAIN_RATE/1e6:.2f} MH/s")
    print(f"  node defaults: PLOT_N={NODE_DEFAULT_PLOT_N} δ={NODE_DEFAULT_DELTA} "
          f"challenge_timeout={CHALLENGE_TIMEOUT}s")
    print(f"  sizes={sizes} deltas={deltas} repeats={args.repeats} challenges={args.challenges}")

    rows: list[dict] = []
    print("\n== source=component (exact node admission functions) ==")
    for delta in deltas:
        for N in sizes:
            r = component_row(N, delta, args.repeats, args.challenges)
            rows.append(r)
            print(f"  δ={delta} N=2^{r['log2_size']:<2d} plot {r['t_plot_ms']:8.3f} ms  "
                  f"commit {r['t_commit_ms']:7.3f} ms  prove {r['t_prove_ms']:.3f}  "
                  f"verify {r['t_verify_ms']:.3f}  admission {r['t_admission_ms']:8.3f} ms  "
                  f"({r['labels_per_s']/1e3:.0f} klab/s, proof {r['proof_bytes']:.0f} B)")

    if not args.component_only:
        print("\n== source=ring_inproc (real in-process 8-node create()/join()) ==")
        for delta in deltas:
            for N in sizes:
                r = ring_row(N, delta, max(1, min(args.repeats, 3)))  # ring is heavier; cap repeats
                rows.append(r)
                print(f"  δ={delta} N=2^{r['log2_size']:<2d} join {r['t_admission_ms']:8.3f} "
                      f"± {r['t_admission_sd']:.3f} ms  [{r['note'].split('founder')[-1]}]")

    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
