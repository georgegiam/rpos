"""Part 4: extrapolate the checkpoint attack to the thesis size N = 3,355,443,200
(100 GiB of 32-byte leaves) using the MEASURED single-core chain rate.

The thesis theorem wants a response timeout delta with  t_store < delta < t_recompute,
assuming a cheater must recompute the WHOLE tree, t_recompute = O(N log N). The checkpoint
attack destroys that: a cheater keeps the upper tree + one label per k-segment and recomputes
only ONE segment per challenge, so t_recompute collapses to O(k). The cheater then picks k as
large as the timeout allows, minimising storage.

Response-time budget (verifier measures wall-clock from challenge sent to answer received):
    response = RTT + work
  honest:  work = disk reads of ~2*(log2 N + 1) tree nodes  -> honest_disk time
  cheater: work = recompute one segment: k sequential chain steps + build its k-leaf subtree.
           The two opened leaves (i-1, i) are in <=2 segments, done on separate cores, so the
           LATENCY critical path is ~2k hashes (k chain steps + ~k subtree hashes). A single
           core does ~4k. Both reported.

For each delta and RTT we give the largest k a cheater can use while still answering within
delta, and the storage fraction (~1.5/k, checkpoint attack, ZERO detection risk) that k implies.

Standalone. Reads results/chainrate.csv and results/honest_disk.csv; writes
results/results_extrapolation.csv.
"""
import csv, math
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
N = 3_355_443_200
LOG2N = math.ceil(math.log2(N))                       # 32 (2^32 = 4.29e9 >= N)
HONEST_STORE = 32 * (2 * N - 1)                        # full tree, ~200 GiB
READS_PER_RESP = 2 * (LOG2N + 1)                       # ~66 node reads


def load_rate():
    p = RES / "chainrate.csv"
    if p.exists():
        for r in csv.reader(open(p)):
            if r and r[0] == "median":
                return float(r[1]) * 1e6
    return 20.36e6
RATE = load_rate()                                     # hashes/s, single core


def measured_ssd_read_s():
    """Best measured per-node uncached SSD read time, from the largest (least-cached) tree
    in honest_disk.csv (N=2^24, a 1 GiB file)."""
    best = None
    p = RES / "honest_disk.csv"
    if p.exists():
        for row in csv.DictReader(open(p)):
            per = float(row["honest_disk_resp_s"]) / int(row["reads_per_resp"])
            log2n = int(row["log2N"])
            if best is None or log2n >= best[0]:
                best = (log2n, per)
    return best[1] if best else 16e-9
PER_READ = measured_ssd_read_s()                       # s per random 32-B node read (SSD)


def largest_pow2_le(x):
    if x < 1:
        return 0
    return 1 << int(math.floor(math.log2(x)))


def run():
    # honest disk time at thesis scale (200 GiB tree cannot be cached in 16 GiB RAM;
    # measured per-read is a fast/partly-cached lower bound, 80us is a conservative NVMe QD1 upper bound)
    honest_disk_meas = READS_PER_RESP * PER_READ
    honest_disk_cons = READS_PER_RESP * 80e-6
    print(f"chain rate (measured, 1 core): {RATE/1e6:.2f} MH/s")
    print(f"N = {N:,}  (log2N ~ {LOG2N})   honest full-tree storage ~ {HONEST_STORE/2**30:.1f} GiB")
    print(f"honest disk work per response: {READS_PER_RESP} node reads")
    print(f"  measured per-read {PER_READ*1e6:.2f} us -> honest_disk ~ {honest_disk_meas*1e3:.2f} ms "
          f"(fast/partly-cached lower bound)")
    print(f"  conservative 80 us/read       -> honest_disk ~ {honest_disk_cons*1e3:.2f} ms (uncached NVMe)")
    print(f"  (an HDD at ~7 ms/seek would be ~{READS_PER_RESP*7:.0f} ms -- but this machine has no HDD)\n")

    deltas = [0.1, 0.5, 1.0, 2.0, 5.0]
    rtts = [0.05, 0.15, 0.30]                           # 50, 150, 300 ms round trip
    rows = []
    print(f"{'delta':>6} {'RTT':>5} | {'honest_ok':>9} {'honest_resp':>11} | "
          f"{'cheat budget':>12} {'k_max(par)':>11} {'store frac':>10} {'store abs':>10} "
          f"{'t_cheat':>8} | separation?")
    print("-" * 108)
    for delta in deltas:
        for rtt in rtts:
            honest_resp = rtt + honest_disk_cons        # use conservative honest disk
            honest_ok = honest_resp <= delta
            budget = delta - rtt                        # cheater compute budget (no disk)
            # latency model: parallel 2 cores -> 2k hashes on critical path; serial -> 4k
            k_par = largest_pow2_le(budget * RATE / 2) if budget > 0 else 0
            k_ser = largest_pow2_le(budget * RATE / 4) if budget > 0 else 0
            k_par = min(k_par, largest_pow2_le(N))
            k_ser = min(k_ser, largest_pow2_le(N))
            frac_par = (1.5 / k_par) if k_par else float("inf")
            frac_ser = (1.5 / k_ser) if k_ser else float("inf")
            store_abs_par = frac_par * HONEST_STORE if k_par else float("inf")
            t_cheat_par = (2 * k_par) / RATE if k_par else float("inf")
            # separation exists only if honest can meet delta but NO storage-saving cheater can.
            # A cheater can always pick a tiny k (t_cheat ~ us) and meet any delta honest meets,
            # so whenever honest_ok, the cheater also passes -> no separation.
            separation = "NONE" if honest_ok else ("honest-fails" if budget <= 0 else "honest-fails")
            rows.append(dict(
                delta_s=delta, rtt_s=rtt,
                honest_disk_cons_s=honest_disk_cons, honest_resp_s=honest_resp,
                honest_meets_delta=honest_ok,
                cheat_compute_budget_s=budget,
                k_max_parallel=k_par, log2_k_max_parallel=(k_par.bit_length()-1 if k_par else None),
                store_fraction_parallel=frac_par,
                store_abs_bytes_parallel=store_abs_par,
                t_cheat_parallel_s=t_cheat_par,
                k_max_serial=k_ser,
                store_fraction_serial=frac_ser,
                separation=separation))
            def fmtk(k): return f"2^{k.bit_length()-1}" if k else "-"
            print(f"{delta:>6.1f} {rtt*1e3:>4.0f}m | {str(honest_ok):>9} {honest_resp*1e3:>9.1f}ms | "
                  f"{budget*1e3:>10.0f}ms {fmtk(k_par):>11} {frac_par*100:>9.4f}% "
                  f"{store_abs_par/2**20:>8.2f}MiB {t_cheat_par*1e3:>6.1f}ms | {separation}")

    with open(RES / "results_extrapolation.csv", "w", newline="") as f:
        w = csv.DictWriter(f, rows[0].keys()); w.writeheader(); w.writerows(rows)
    print(f"\nWrote results/results_extrapolation.csv ({len(rows)} rows).")
    print("\nBottom line: for every (delta, RTT) where the honest node can answer at all, the "
          "cheater can too -- storing at most a few MiB (parts-per-million of 200 GiB) and often "
          "answering FASTER than the honest node reads its disk. No delta separates them.")


if __name__ == "__main__":
    run()
