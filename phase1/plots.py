"""Part 6: plots for the Phase 1 risk check. Reads the CSVs in results/ and writes PNGs.

v2 (chain) figures:
  fig_tradeoff.png            - measured checkpoint trade-off: storage fraction vs cheater
                                response time, one line per N, with the delta timeout lines
                                and the honest on-disk response time marked.
  fig_thesis_extrapolation.png- at the thesis size N=3.355e9: minimum cheater storage vs the
                                response-timeout delta, for RTT in {50, 300} ms.
  fig_reset_detection.png     - segment-reset attack: detection probability vs k for
                                c in {1,10,50,100} challenges per round.

Fix A (v3 DRG) figures -- issue #6, each with a tidy companion CSV of exactly the plotted rows:
  fig_money.png / .csv        - (a) THE money plot: recompute hashes/challenge vs storage
                                fraction, v2 chain vs v3 DRG (in-degree 2/4/8) at fixed N; twin
                                axis reads response seconds at the measured chain rate.
  fig_separation.png / .csv   - (b) delta-separation before/after: min cheater storage vs the
                                response-timeout delta, v2 (parts-per-million) vs v3 (~full).
  fig_proof_verify.png / .csv - (c) the honest cost Fix A charges: proof size and verify time
                                vs the DRG in-degree delta, one line per N.

NB: `delta` is overloaded. In the v3 sweep it is the DRG IN-DEGREE knob (2/4/8) -- that is the
x-axis of (c). The response TIMEOUT (0.1..5 s) is a separate quantity, the x-axis of (b).

Design: colorblind-safe categorical hues in fixed order (validated dataviz palette), log
axes, recessive grid, direct-labelled delta lines. Standalone.
"""
import csv, math
from collections import defaultdict
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

HERE = Path(__file__).resolve().parent
RES = HERE / "results"

# validated colorblind-safe categorical palette (light mode), fixed order
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"]
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
DELTA_C = "#8a1c5a"      # reserved accent for the timeout lines (not a series hue)
DELTAS = [0.1, 0.5, 1.0, 2.0, 5.0]

plt.rcParams.update({
    "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
    "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 11,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.axisbelow": True, "figure.dpi": 150,
})

def read_csv(name):
    with open(RES / name) as f:
        return list(csv.DictReader(f))

def write_csv(name, fieldnames, rows):
    """Write a tidy companion CSV (exactly the plotted series) next to its figure."""
    with open(RES / name, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader(); w.writerows(rows)
    print(f"wrote {name}")

RATE = 20.36e6
for r in (read_csv("chainrate.csv")):
    if r.get("run") == "median":
        RATE = float(r["MH_per_s"]) * 1e6


# ---------------------------------------------------------------- Figure 1
def fig_tradeoff():
    rows = read_csv("results_v2_checkpoint.csv")
    by_N = defaultdict(list)
    for r in rows:
        by_N[int(r["log2N"])].append((float(r["cheat_resp_at_crate_s"]),
                                      float(r["storage_fraction"]),
                                      int(r["log2k"])))
    honest = {int(r["log2N"]): float(r["honest_disk_resp_s"]) for r in read_csv("honest_disk.csv")}

    fig, ax = plt.subplots(figsize=(9, 6))
    # analytic trade-off curve extended across the delta region: t = 2k/RATE, frac = 1.5/k
    ts = [10**e for e in [x / 40 for x in range(-230, 60)]]      # ~1e-5.7 .. 1e1.5 s
    frac = [3.0 / (t * RATE) for t in ts]                        # = 1.5/k with k=t*RATE/2
    ax.plot(ts, frac, color=MUTED, lw=1.2, ls="--", zorder=2,
            label="analytic 1.5/k envelope (any N)")

    for idx, logN in enumerate(sorted(by_N)):
        pts = sorted(by_N[logN])
        xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
        ax.plot(xs, ys, color=SERIES[idx], lw=2, marker="o", ms=6,
                markeredgecolor="#fcfcfb", markeredgewidth=1.2, zorder=4,
                label=f"N = 2^{logN}")
    # k labels on the largest-N curve
    for x, y, logk in sorted(by_N[max(by_N)]):
        ax.annotate(f"k=2^{logk}", (x, y), textcoords="offset points", xytext=(4, 6),
                    fontsize=8, color=MUTED)

    # delta timeout lines, with the cheater storage the envelope allows at each delta
    for d in DELTAS:
        ax.axvline(d, color=DELTA_C, lw=1.1, ls=":", zorder=3)
        ax.annotate(f"δ={d:g}s", (d, 60), rotation=90, va="top", ha="right",
                    fontsize=8.5, color=DELTA_C)
        fr = 3.0 / (d * RATE)
        ax.plot([d], [fr], marker="*", ms=11, color=DELTA_C, zorder=5,
                markeredgecolor="#fcfcfb", markeredgewidth=0.8)
    ax.annotate(f"≈{3.0/(DELTAS[0]*RATE):.0e}\nof honest", (DELTAS[0], 3.0/(DELTAS[0]*RATE)),
                textcoords="offset points", xytext=(6, 0), fontsize=8, color=DELTA_C, va="center")

    # honest on-disk response band: realistic UNCACHED thesis-scale estimate (~1-5 ms).
    # (The in-cache micro-measurements were faster; see FINDINGS caveat.)
    ax.axvspan(1e-3, 5e-3, color="#1baf7a", alpha=0.14, zorder=1)
    ax.annotate("honest disk read\n(uncached est., ~1–5 ms)", (5e-3, 8e-6), fontsize=8.5,
                color="#0f7a55", ha="center", va="bottom")

    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("cheater response time  (s, at measured 20.4 MH/s single core)")
    ax.set_ylabel("cheater storage  /  honest storage")
    ax.set_title("v2 checkpoint attack: storage vs response time (all N overlap)\n"
                 "every real timeout δ (★) sits where the cheater stores a negligible fraction",
                 fontsize=12)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: f"{v*100:g}%" if v >= 1e-4 else f"{v:.0e}"))
    ax.set_ylim(1e-7, 1.5); ax.set_xlim(1e-6, 3e1)
    ax.legend(loc="upper right", frameon=False, fontsize=9)
    fig.tight_layout(); fig.savefig(RES / "fig_tradeoff.png"); plt.close(fig)
    print("wrote fig_tradeoff.png")


# ---------------------------------------------------------------- Figure 2
def fig_thesis():
    rows = read_csv("results_extrapolation.csv")
    by_rtt = defaultdict(list)
    for r in rows:
        if r["k_max_parallel"] and int(r["k_max_parallel"]) > 0:
            by_rtt[float(r["rtt_s"])].append((float(r["delta_s"]),
                                              float(r["store_fraction_parallel"]),
                                              int(r["k_max_parallel"])))
    fig, ax = plt.subplots(figsize=(9, 6))
    for idx, rtt in enumerate(sorted(by_rtt)):
        pts = sorted(by_rtt[rtt])
        xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
        ax.plot(xs, ys, color=SERIES[idx], lw=2, marker="o", ms=7,
                markeredgecolor="#fcfcfb", markeredgewidth=1.2,
                label=f"RTT = {rtt*1e3:.0f} ms")
        for d, fr, k in pts:
            ax.annotate(f"k=2^{k.bit_length()-1}", (d, fr), textcoords="offset points",
                        xytext=(4, 6), fontsize=8, color=MUTED)
    ax.axhline(1.0, color=INK, lw=1.2)
    ax.annotate("honest node = 100% (≈200 GiB)", (5, 1.0), textcoords="offset points",
                xytext=(-4, 6), ha="right", fontsize=9, color=INK)
    ax.set_yscale("log")
    ax.set_xlabel("response timeout  δ  (s)")
    ax.set_ylabel("minimum cheater storage / 200 GiB honest storage")
    ax.set_title("Thesis scale (N = 3.355×10⁹, 200 GiB): storage a cheater actually needs\n"
                 "for every δ where an honest node can answer, the cheater needs parts-per-million",
                 fontsize=12)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: f"{v*100:g}%" if v >= 1e-4 else f"{v:.0e}"))
    ax.legend(loc="center right", frameon=False, fontsize=9)
    fig.tight_layout(); fig.savefig(RES / "fig_thesis_extrapolation.png"); plt.close(fig)
    print("wrote fig_thesis_extrapolation.png")


# ---------------------------------------------------------------- Figure 3
def fig_reset():
    rows = read_csv("results_v2_reset.csv")
    by_c = defaultdict(list)
    for r in rows:
        by_c[int(r["c"])].append((int(r["log2k"]), float(r["p_detect_analytic"]),
                                  float(r["p_detect_sim"])))
    fig, ax = plt.subplots(figsize=(9, 6))
    for idx, c in enumerate(sorted(by_c)):
        pts = sorted(by_c[c])
        xs = [p[0] for p in pts]; ya = [p[1] for p in pts]; ys = [p[2] for p in pts]
        ax.plot(xs, ya, color=SERIES[idx], lw=2, label=f"c = {c} challenges/round")
        ax.plot(xs, ys, color=SERIES[idx], lw=0, marker="x", ms=6)   # Monte-Carlo points
    ax.axhline(0.01, color=MUTED, ls=":", lw=1)
    ax.annotate("1% per-round detection", (16, 0.01), textcoords="offset points",
                xytext=(-4, 4), ha="right", fontsize=8.5, color=MUTED)
    ax.set_yscale("log")
    ax.set_xlabel("segment length  k  (log₂)")
    ax.set_ylabel("per-round detection probability")
    ax.set_title("Segment-reset attack: detection vs k  (lines = analytic, × = Monte-Carlo)\n"
                 "N = 3.355×10⁹; larger k hides the cheater but costs O(k) recompute",
                 fontsize=12)
    ax.set_ylim(1e-4, 1.2)
    ax.legend(loc="lower left", frameon=False, fontsize=9)
    fig.tight_layout(); fig.savefig(RES / "fig_reset_detection.png"); plt.close(fig)
    print("wrote fig_reset_detection.png")


# ============================================================ Fix A (issue #6) ============
V3_DELTAS = [2, 4, 8]            # DRG in-degree knob
DELTA_HUE = {2: SERIES[2], 4: SERIES[3], 8: SERIES[4]}   # greens/ambers for the v3 in-degrees
V2_HUE = SERIES[1]              # orange -- the (broken) chain, matches the v2 figures' accent


# ---------------------------------------------------------------- Figure (a): the money plot
def fig_money():
    """recompute hashes/challenge vs storage fraction, v2 chain vs v3 DRG, at the largest N
    common to both sweeps. Twin right axis = response seconds at the measured chain rate."""
    v2 = read_csv("results_v2_checkpoint.csv")
    v3 = read_csv("results_v3_retain.csv")
    n2 = {int(r["log2N"]) for r in v2}
    n3 = {int(r["log2N"]) for r in v3}
    logN = max(n2 & n3)          # 2^22: largest size measured in BOTH v2 and v3

    fig, ax = plt.subplots(figsize=(9, 6))
    out = []

    # v2 chain: (storage_fraction, nhash_worst) matched by checkpoint spacing k
    v2pts = sorted((float(r["storage_fraction"]), int(r["nhash_worst"]), int(r["k"]))
                   for r in v2 if int(r["log2N"]) == logN and int(r["nhash_worst"]) > 0)
    ax.plot([p[0] for p in v2pts], [p[1] for p in v2pts], color=V2_HUE, lw=2.2,
            marker="o", ms=6, markeredgecolor="#fcfcfb", markeredgewidth=1.2, zorder=5,
            label="v2 chain (O(k), flat in N)")
    for frac, nh, k in v2pts:
        out.append(dict(scheme="v2_chain", indeg="", param_k_or_s=k, log2N=logN,
                        storage_fraction=frac, recompute_hashes=nh, saturated=0))

    # v3 DRG: one line per in-degree; (storage_fraction, rec_hashes_median), skip full-store s=1
    for idx, d in enumerate(V3_DELTAS):
        pts = sorted((float(r["storage_fraction"]), int(r["rec_hashes_median"]),
                      int(r["s"]), int(r["saturated"]))
                     for r in v3 if int(r["log2N"]) == logN and int(r["delta"]) == d
                     and int(r["rec_hashes_median"]) > 0)
        ax.plot([p[0] for p in pts], [p[1] for p in pts], color=DELTA_HUE[d], lw=2.2,
                marker="o", ms=6, markeredgecolor="#fcfcfb", markeredgewidth=1.2, zorder=4,
                label=f"v3 DRG, in-degree δ={d}")
        # mark saturated points (back-cone ≈ whole graph -> recompute ~ full replot)
        sat = [(f, h) for f, h, s, st in pts if st]
        if sat:
            ax.plot([p[0] for p in sat], [p[1] for p in sat], color=DELTA_HUE[d], lw=0,
                    marker="s", ms=9, markerfacecolor="none", markeredgewidth=1.6, zorder=6)
        for frac, nh, s, st in pts:
            out.append(dict(scheme="v3_drg", indeg=d, param_k_or_s=s, log2N=logN,
                            storage_fraction=frac, recompute_hashes=nh, saturated=st))

    ax.plot([], [], color=MUTED, lw=0, marker="s", ms=9, markerfacecolor="none",
            markeredgewidth=1.6, label="v3 saturated (back-cone ≈ whole graph)")

    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("cheater storage  /  honest storage")
    ax.set_ylabel("recompute hashes per challenge")
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: f"{v*100:g}%" if v >= 1e-4 else f"{v:.0e}"))
    # twin axis: same data as seconds at the measured native chain rate
    sec = ax.secondary_yaxis("right", functions=(lambda h: h / RATE, lambda t: t * RATE))
    sec.set_ylabel(f"cheater response time  (s, at {RATE/1e6:.1f} MH/s single core)")
    ax.set_title(f"The money plot (N = 2^{logN}): recompute cost a cheater pays per challenge\n"
                 "v2 chain gives it away for parts-per-million storage; v3 DRG forces near-O(N)",
                 fontsize=12)
    ax.legend(loc="lower left", frameon=False, fontsize=9)
    fig.tight_layout(); fig.savefig(RES / "fig_money.png"); plt.close(fig)
    print("wrote fig_money.png")
    write_csv("fig_money.csv",
              ["scheme", "indeg", "param_k_or_s", "log2N", "storage_fraction",
               "recompute_hashes", "saturated"], out)


# ---------------------------------------------------------------- Figure (b): δ-separation
def fig_separation(rtt_s=0.05):
    """min cheater storage fraction vs the response-timeout δ: v2 (before, parts-per-million)
    vs v3 (after, ~full). Fixed RTT so every timeout is feasible for the honest node."""
    rows = [r for r in read_csv("results_delta_separation.csv")
            if abs(float(r["rtt_s"]) - rtt_s) < 1e-9 and r["honest_meets_delta"] == "True"]
    fig, ax = plt.subplots(figsize=(9, 6))
    out = []

    # v2 (before): v2_min_store_frac depends only on (δ, rtt) -> read it from one in-degree group
    v2pts = sorted({(float(r["delta_s"]), float(r["v2_min_store_frac"]))
                    for r in rows if int(r["delta"]) == V3_DELTAS[0] and r["v2_min_store_frac"]})
    if v2pts:
        ax.plot([p[0] for p in v2pts], [p[1] for p in v2pts], color=V2_HUE, lw=2.4,
                marker="o", ms=7, markeredgecolor="#fcfcfb", markeredgewidth=1.2, zorder=5,
                label="v2 chain (before): no separating δ")
        for d, fr in v2pts:
            out.append(dict(scheme="v2_chain", indeg="", rtt_s=rtt_s, delta_timeout_s=d,
                            min_store_fraction=fr))

    # v3 (after): min_store_frac_seq per in-degree
    for d in V3_DELTAS:
        pts = sorted((float(r["delta_s"]), float(r["min_store_frac_seq"]))
                     for r in rows if int(r["delta"]) == d)
        ax.plot([p[0] for p in pts], [p[1] for p in pts], color=DELTA_HUE[d], lw=2.2,
                marker="o", ms=6, markeredgecolor="#fcfcfb", markeredgewidth=1.2, zorder=4,
                label=f"v3 DRG (after), δ_indeg={d}")
        for dt, fr in pts:
            out.append(dict(scheme="v3_drg", indeg=d, rtt_s=rtt_s, delta_timeout_s=dt,
                            min_store_fraction=fr))

    ax.axhline(1.0, color=INK, lw=1.2)
    ax.annotate("honest node = 100% storage", (5.0, 1.0), textcoords="offset points",
                xytext=(-4, 6), ha="right", fontsize=9, color=INK)
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xticks(sorted({float(r["delta_s"]) for r in rows}))
    ax.get_xaxis().set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:g}"))
    ax.set_xlabel(f"response timeout  δ  (s)   [RTT fixed at {rtt_s*1e3:.0f} ms]")
    ax.set_ylabel("minimum cheater storage / honest storage")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(
        lambda v, _: f"{v*100:g}%" if v >= 1e-4 else f"{v:.0e}"))
    ax.set_title("δ-separation, before vs after Fix A (thesis N = 3.355×10⁹)\n"
                 "chain: cheater always stores ppm; DRG: cheater forced to ~full storage",
                 fontsize=12)
    ax.legend(loc="center right", frameon=False, fontsize=9)
    fig.tight_layout(); fig.savefig(RES / "fig_separation.png"); plt.close(fig)
    print("wrote fig_separation.png")
    write_csv("fig_separation.csv",
              ["scheme", "indeg", "rtt_s", "delta_timeout_s", "min_store_fraction"], out)


# ---------------------------------------------------------------- Figure (c): proof + verify cost
def fig_proof_verify():
    """proof size and verify time vs the DRG in-degree δ, one line per N -- the honest cost."""
    rows = read_csv("results_bench_v3.csv")
    logNs = sorted({int(r["log2N"]) for r in rows})
    fig, (axl, axr) = plt.subplots(1, 2, figsize=(12, 5.2))
    out = []

    for idx, logN in enumerate(logNs):
        rs = sorted((int(r["delta"]), int(r["proof_bytes_median"]),
                     int(r["proof_bytes_analytic"]), float(r["verify_us_median"]),
                     float(r["verify_us_p99"])) for r in rows if int(r["log2N"]) == logN)
        ds = [r[0] for r in rs]
        axl.plot(ds, [r[1] / 1024 for r in rs], color=SERIES[idx], lw=2, marker="o", ms=6,
                 markeredgecolor="#fcfcfb", markeredgewidth=1.2, label=f"N = 2^{logN}")
        axr.plot(ds, [r[3] for r in rs], color=SERIES[idx], lw=2, marker="o", ms=6,
                 markeredgecolor="#fcfcfb", markeredgewidth=1.2, label=f"N = 2^{logN}")
        for d, pb, pa, vm, vp in rs:
            out.append(dict(log2N=logN, indeg=d, proof_bytes_median=pb,
                            proof_bytes_analytic=pa, proof_KiB=round(pb / 1024, 3),
                            verify_us_median=vm, verify_us_p99=vp))

    # analytic proof-size check (largest N): (1+δ)*(1+log2N)*32 -- should sit on the measured line
    logN = logNs[-1]
    an = sorted((int(r["delta"]), int(r["proof_bytes_analytic"]))
                for r in rows if int(r["log2N"]) == logN)
    axl.plot([a[0] for a in an], [a[1] / 1024 for a in an], color=MUTED, lw=1.1, ls="--",
             zorder=2, label="analytic (1+δ)(1+log₂N)·32")

    for ax in (axl, axr):
        ax.set_xticks(V3_DELTAS)
        ax.set_xlabel("DRG in-degree  δ  (parents opened = 1+δ)")
    axl.set_ylabel("proof size per challenge  (KiB)")
    axr.set_ylabel("verify time per challenge  (µs, Python)")
    axl.set_title("Proof size vs in-degree", fontsize=12)
    axr.set_title("Verify time vs in-degree", fontsize=12)
    axl.legend(loc="upper left", frameon=False, fontsize=9)
    axr.legend(loc="upper left", frameon=False, fontsize=9)
    fig.suptitle("What Fix A charges the honest verifier: proof = (1+δ) Merkle paths, "
                 "verify a few tens of µs", fontsize=12.5)
    fig.tight_layout(); fig.savefig(RES / "fig_proof_verify.png"); plt.close(fig)
    print("wrote fig_proof_verify.png")
    write_csv("fig_proof_verify.csv",
              ["log2N", "indeg", "proof_bytes_median", "proof_bytes_analytic", "proof_KiB",
               "verify_us_median", "verify_us_p99"], out)


if __name__ == "__main__":
    fig_tradeoff()
    fig_thesis()
    fig_reset()
    fig_money()
    fig_separation()
    fig_proof_verify()
    print("all figures in results/")
