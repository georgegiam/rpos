"""Fix A, step 5 (issue #5): bench_v3.py -- the COST side of Fix A.

attack_v3_retain.py / delta_separation_drg.py show what Fix A BUYS (a real space guarantee:
the retention attack's back-cone climbs toward O(N), so a usable timeout delta separates
honest from cheater). This script measures what the honest node PAYS for it, for the v3
DRG-labelled scheme (pospace_drg.py) at delta in {2,4,8}:

  (1) plotting throughput -- labels/s and MiB/s, measured in Python (apples-to-apples with the
      old rpos.py 100 GiB number, which was also pure Python), split into graph-sampling vs
      label-hashing, plus a native-rate FLOOR (what an optimised C plotter could do).
  (2) RAM-resident vs would-need-disk crossover -- the labels array is 32*N bytes; once it
      exceeds RAM, a label's DRG parents (DRSample back-edges reach up to ~i/2) become random
      SSD reads. We compute the crossover N, MEASURE the parent back-distance distribution, and
      model the added I/O cost at the thesis size.
  (3) proof size -- measured bytes of prove_v3's output = (1+delta) Merkle paths (opens node i
      and its parents), checked against the analytic (1+delta)*(1+log2 N)*32.
  (4) verify time per challenge -- measured wall-clock + a native-rate model.
  (5) one extrapolated "plotting time at 100 GiB" (N = 3,355,443,200) to REPLACE the old 1h38m.
      HEADLINE = the Python extrapolation (same language as the old number); we also give the
      native floor and the +random-I/O correction. NB: the old 1h38m must itself be re-measured
      after the rpos.py threading fix (FINDINGS.md Finding 0: num_threads=4 emitted ~75%
      duplicate data, inflating the apparent plot rate), so it is a known-inflated baseline.

Reuses pospace.py Merkle primitives, drg.py, and pospace_drg.py; does NOT modify rpos.py or
v1/v2. Standalone, fixed seed. Reads results/{chainrate,env,honest_disk}.csv; writes
results/results_bench_v3.csv (per N,delta) and results/results_plot_extrap_v3.csv (per delta).
Figures for these live in plots.py (issue #6, panel c).
"""
import csv, statistics, time
from pathlib import Path

from pospace import build_tree, node, merkle_path            # noqa: F401 (build_tree via commit_v3)
from pospace_drg import plot_v3, commit_v3, prove_v3, verify_v3
from drg import parents, parents_all

HERE = Path(__file__).resolve().parent
RES = HERE / "results"; RES.mkdir(exist_ok=True)
SEED = 1

# sweep -- N up to what plots in pure Python in a couple of minutes (2^22 = 128 MiB of labels).
# All three N confirm the O(N) linearity the 100 GiB extrapolation relies on. Tunable.
NS = [2**18, 2**20, 2**22]
DELTAS = [2, 4, 8]
THESIS_N = 3_355_443_200                  # 100 GiB of 32-byte labels (matches extrapolate.py)

PROOF_CHALLENGES = 200                     # proofs to serialise-measure per config
VERIFY_CHALLENGES = 1000                   # verify calls to time per config
PARENT_DIST_SAMPLE = 100_000               # nodes sampled for the back-distance distribution


# --- measured single-core native SHA-256 rate (shared convention with the attack scripts) ---
def load_chain_rate(default_mhs=20.36):
    p = RES / "chainrate.csv"
    if p.exists():
        for r in csv.reader(open(p)):
            if r and r[0] == "median":
                return float(r[1]) * 1e6
    return default_mhs * 1e6
CHAIN_RATE = load_chain_rate()             # hashes / s, native single core


def pct(xs, q):
    """Nearest-rank percentile (q in [0,1]); xs need not be sorted."""
    if not xs:
        return float("nan")
    s = sorted(xs)
    k = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return s[k]


def sha_blocks(nbytes):
    """SHA-256 compression blocks for an nbyte message (message + 0x80 + 8-byte length, /64)."""
    return (nbytes + 9 + 63) // 64
# The chainrate.c / v2 chain hashes h_{i-1}(32) || pk(33) || i(8) = 73 B; CHAIN_RATE is that
# per-hash rate. A v3 label hashes pk(33) || i(8) || parents*32, so it costs more blocks per hash.
CHAIN_INPUT_BYTES = 32 + 33 + 8
BLOCKS_CHAIN = sha_blocks(CHAIN_INPUT_BYTES)
PK_BYTES = 33                              # compressed pubkey (as used across the scripts)
LABEL_FIXED = PK_BYTES + 8                 # pk || i.to_bytes(8) before the parent labels


def load_ram_gib(default=16.0):
    p = RES / "env.csv"
    if p.exists():
        for r in csv.DictReader(open(p)):
            if r.get("key") == "ram_GiB":
                try:
                    return float(r["value"])
                except ValueError:
                    pass
    return default


def measured_ssd_read_s(default=16e-9):
    """Best measured per-node uncached SSD read from the largest tree in honest_disk.csv."""
    best = None
    p = RES / "honest_disk.csv"
    if p.exists():
        for row in csv.DictReader(open(p)):
            per = float(row["honest_disk_resp_s"]) / int(row["reads_per_resp"])
            log2n = int(row["log2N"])
            if best is None or log2n >= best[0]:
                best = (log2n, per)
    return best[1] if best else default
PER_READ = measured_ssd_read_s()           # s per random 32-B node read (SSD)
CONS_READ = 80e-6                           # conservative uncached NVMe QD1 (per extrapolate.py)

RAM_GIB = load_ram_gib()
USABLE_FRAC = 0.75                          # leave headroom for the OS, parent table, page cache
N_RAM = int(USABLE_FRAC * RAM_GIB * 2**30 // 32)   # labels that fit in usable RAM


# ============================ per-config benchmark ============================
def bench_config(pk, N, delta, rng):
    logN = N.bit_length() - 1

    # -- graph generation (timed separately so plotting splits into sample vs hash) --
    t0 = time.perf_counter(); P = parents_all(N, pk, delta); t_parents = time.perf_counter() - t0
    indegs = [len(p) for p in P]
    avg_indeg = sum(indegs) / N
    mean_blocks = sum(sha_blocks(LABEL_FIXED + d * 32) for d in indegs) / N

    # -- full plotting (plot_v3 regenerates the graph internally; report its real cost) --
    t0 = time.perf_counter(); labels = plot_v3(pk, N, delta); t_plot = time.perf_counter() - t0
    t_labelhash = max(t_plot - t_parents, t_plot * 1e-6)   # pure label loop (>=0)
    labels_per_s = N / t_plot
    mib_per_s = (32 * N / 2**20) / t_plot
    plot_time_native_s = N * (mean_blocks / BLOCKS_CHAIN) / CHAIN_RATE   # optimised floor

    # -- commitment + proof size (measured) --
    levels, root = commit_v3(labels)
    sizes, nopens, prove_ts = [], [], []
    for _ in range(PROOF_CHALLENGES):
        i = rng.randrange(1, N)
        t0 = time.perf_counter(); proof = prove_v3(levels, pk, N, delta, i)
        prove_ts.append(time.perf_counter() - t0)
        sizes.append(sum(len(lbl) + 32 * len(path) for (lbl, path) in proof.values()))
        nopens.append(len(proof))
    proof_bytes_median = int(statistics.median(sizes))
    proof_bytes_max = max(sizes)
    nopen_mean = statistics.mean(nopens)
    proof_bytes_analytic = (1 + delta) * (1 + logN) * 32          # (1+delta) full Merkle paths

    # -- verify time per challenge (measured + native model) --
    vts = []
    for _ in range(VERIFY_CHALLENGES):
        i = rng.randrange(1, N)
        proof = prove_v3(levels, pk, N, delta, i)
        t0 = time.perf_counter(); ok = verify_v3(root, pk, N, delta, i, proof)
        vts.append(time.perf_counter() - t0)
        assert ok, f"verify_v3 failed at N=2^{logN} delta={delta} i={i}"
    verify_us_median = statistics.median(vts) * 1e6
    verify_us_p99 = pct(vts, 0.99) * 1e6
    nhash_verify = nopen_mean * logN + 1                         # root_from_path per node + label eq
    verify_native_us = nhash_verify / CHAIN_RATE * 1e6

    row = dict(
        log2N=logN, N=N, delta=delta,
        avg_indeg=round(avg_indeg, 4), mean_sha_blocks=round(mean_blocks, 4),
        labels_per_s_py=round(labels_per_s, 1), MiB_per_s_py=round(mib_per_s, 3),
        plot_s_total=round(t_plot, 4), parent_sample_s=round(t_parents, 4),
        label_hash_s=round(t_labelhash, 4), plot_time_native_s=round(plot_time_native_s, 6),
        n_open_mean=round(nopen_mean, 3),
        proof_bytes_median=proof_bytes_median, proof_bytes_max=proof_bytes_max,
        proof_bytes_analytic=proof_bytes_analytic,
        prove_us_median=round(statistics.median(prove_ts) * 1e6, 3),
        verify_us_median=round(verify_us_median, 3), verify_us_p99=round(verify_us_p99, 3),
        verify_native_us=round(verify_native_us, 4),
    )
    print(f"  N=2^{logN} d={delta}: plot {labels_per_s/1e3:7.1f} klab/s "
          f"({mib_per_s:6.2f} MiB/s; graph {t_parents:.2f}s + hash {t_labelhash:.2f}s) | "
          f"proof {proof_bytes_median:>6d} B (max {proof_bytes_max}, ~{proof_bytes_analytic}) | "
          f"verify {verify_us_median:6.1f} us (native {verify_native_us:.2f} us)", flush=True)
    return row


# ============================ parent back-distance distribution (RAM crossover) ============================
def parent_distance_stats(pk, N_ref, delta, rng, nsample):
    """Non-path parent back-distances (i-p) over sampled nodes, at reference size N_ref.

    The path edge (i-1) is always adjacent (hot in cache); the (delta-1) extra DRSample edges
    reach geometrically far (up to ~i/2). We report absolute distance and its fraction of i.
    """
    rel, absd = [], []
    for _ in range(nsample):
        i = rng.randrange(2, N_ref)
        for p in parents(i, pk, delta):
            if p == i - 1:
                continue
            d = i - p
            absd.append(d)
            rel.append(d / i)
    return rel, absd


# ============================ driver ============================
def run():
    import random
    rng = random.Random(SEED)
    pk = bytes(rng.getrandbits(8) for _ in range(PK_BYTES))

    print(f"native SHA-256 rate: {CHAIN_RATE/1e6:.2f} MH/s (per {BLOCKS_CHAIN}-block chain hash)")
    print(f"RAM {RAM_GIB:.1f} GiB -> usable {USABLE_FRAC:.0%} -> labels fit in RAM up to "
          f"N_ram = {N_RAM:,} ({N_RAM*32/2**30:.1f} GiB of labels)")
    print(f"SSD per-read: measured {PER_READ*1e6:.2f} us (honest_disk.csv), conservative "
          f"{CONS_READ*1e6:.0f} us\n")

    rows = []
    for delta in DELTAS:                    # group by delta for readable linearity check
        for N in NS:
            rows.append(bench_config(pk, N, delta, rng))
    with open(RES / "results_bench_v3.csv", "w", newline="") as f:
        w = csv.DictWriter(f, rows[0].keys()); w.writeheader(); w.writerows(rows)
    print(f"\nWrote results/results_bench_v3.csv ({len(rows)} rows).")

    # ---- RAM crossover + parent-distance stats at the thesis size ----
    print(f"\n===== RAM-resident vs would-need-disk crossover =====")
    print(f"thesis N = {THESIS_N:,} -> labels = {THESIS_N*32/2**30:.1f} GiB  "
          f">> usable RAM ({N_RAM*32/2**30:.1f} GiB)  -> plotting is in the random-I/O regime.")
    _, absd = parent_distance_stats(pk, THESIS_N, 8, rng, PARENT_DIST_SAMPLE)
    d_med, d_p99, d_max = int(pct(absd, 0.5)), int(pct(absd, 0.99)), max(absd)
    miss_frac = sum(1 for d in absd if d > N_RAM) / len(absd)     # cold (out-of-RAM) parent reads
    print(f"non-path parent back-distance @ thesis N (delta=8): median {d_med:,} "
          f"({d_med*32/2**20:.1f} MiB back), p99 {d_p99:,}, max {d_max:,} "
          f"({d_max*32/2**30:.1f} GiB back)")
    print(f"fraction of non-path parent reads beyond RAM (> {N_RAM:,}): {miss_frac:.3f} "
          f"-> each such read is a random SSD access during plotting.")

    # ---- 100 GiB plotting-time extrapolation, per delta ----
    print(f"\n===== extrapolated plotting time at 100 GiB (replaces old rpos.py 1h38m) =====")
    print("NB: the old 1h38m must be RE-MEASURED after the rpos.py threading fix "
          "(FINDINGS.md Finding 0:\n    num_threads=4 emitted ~75% duplicate labels, "
          "inflating apparent throughput) -- it is a known-inflated baseline.\n")
    hdr = (f"{'delta':>5} {'py klab/s':>10} {'py plot':>10} {'+rand-I/O':>11} "
           f"{'native floor':>13} {'py resp':>9}")
    print(hdr); print("-" * len(hdr))
    extrap_rows = []
    for delta in DELTAS:
        # use the largest-N measurement per delta as the extrapolation base (most representative)
        base = max((r for r in rows if r["delta"] == delta), key=lambda r: r["N"])
        rate = base["labels_per_s_py"]
        avg_nonpath = base["avg_indeg"] - 1                       # extra edges beyond the path edge
        plot_py_s = THESIS_N / rate
        plot_native_s = THESIS_N * (base["mean_sha_blocks"] / BLOCKS_CHAIN) / CHAIN_RATE
        io_meas_s = THESIS_N * avg_nonpath * miss_frac * PER_READ
        io_cons_s = THESIS_N * avg_nonpath * miss_frac * CONS_READ
        plot_py_io_s = plot_py_s + io_meas_s

        def hms(s):
            h, rem = divmod(int(s), 3600); m, sec = divmod(rem, 60)
            return f"{h}h{m:02d}m{sec:02d}s"
        print(f"{delta:>5} {rate/1e3:>10.1f} {hms(plot_py_s):>10} {hms(plot_py_io_s):>11} "
              f"{hms(plot_native_s):>13} {plot_py_s/THESIS_N*1e9:>7.1f}ns")
        extrap_rows.append(dict(
            delta=delta, thesis_N=THESIS_N, thesis_labels_GiB=round(THESIS_N * 32 / 2**30, 2),
            base_log2N=base["log2N"], labels_per_s_py=rate, avg_indeg=base["avg_indeg"],
            mean_sha_blocks=base["mean_sha_blocks"],
            plot_time_100GiB_py_s=round(plot_py_s, 1),
            plot_time_100GiB_py_plus_io_s=round(plot_py_io_s, 1),
            plot_time_100GiB_native_s=round(plot_native_s, 1),
            io_penalty_meas_s=round(io_meas_s, 1), io_penalty_cons_s=round(io_cons_s, 1),
            ram_GiB=RAM_GIB, N_ram=N_RAM, ram_crossover_GiB=round(N_RAM * 32 / 2**30, 2),
            parent_miss_frac_beyond_ram=round(miss_frac, 4),
            parent_dist_median=d_med, parent_dist_p99=d_p99, parent_dist_max=d_max,
            per_read_meas_s=PER_READ, per_read_cons_s=CONS_READ,
        ))
    with open(RES / "results_plot_extrap_v3.csv", "w", newline="") as f:
        w = csv.DictWriter(f, extrap_rows[0].keys()); w.writeheader(); w.writerows(extrap_rows)
    print(f"\nWrote results/results_plot_extrap_v3.csv ({len(extrap_rows)} rows).")
    print("HEADLINE = 'py plot' (pure-Python, apples-to-apples with the old Python rpos.py "
          "number);\n'+rand-I/O' adds the out-of-RAM parent-read penalty; 'native floor' is what "
          "an optimised C\nplotter could reach. Plotting is heavier than the chain (each label "
          "hashes its DRG parents)\n-- that is the cost Fix A trades for a real space guarantee.")


if __name__ == "__main__":
    run()
