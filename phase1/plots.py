"""Part 6: plots for the Phase 1 risk check. Reads the CSVs in results/ and writes PNGs.

Figures:
  fig_tradeoff.png            - measured checkpoint trade-off: storage fraction vs cheater
                                response time, one line per N, with the delta timeout lines
                                and the honest on-disk response time marked.
  fig_thesis_extrapolation.png- at the thesis size N=3.355e9: minimum cheater storage vs the
                                response-timeout delta, for RTT in {50, 300} ms.
  fig_reset_detection.png     - segment-reset attack: detection probability vs k for
                                c in {1,10,50,100} challenges per round.

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


if __name__ == "__main__":
    fig_tradeoff()
    fig_thesis()
    fig_reset()
    print("all figures in results/")
