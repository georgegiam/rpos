"""Attack on v2: the SEGMENT-RESET (no-checkpoint) trade-off.

The checkpoint attack still stores one chain label per segment (32*N/k bytes). The cheater
can drop even those: instead of continuing the real chain across a segment boundary, it
RESETS the chain every k steps to a value it can recompute directly from the public key and
the segment index,
        seg_start_label(s) = H(pk || s)          (no stored checkpoint needed),
then runs the normal step inside the segment. Any segment's k leaves are now regenerable in
<= k steps from pk alone, so the cheater keeps essentially nothing (just pk, and optionally
the ~1/k upper tree for fast paths).

The price: the reset breaks the chain at every segment boundary. For a challenge index i that
is a multiple of k, the verifier's adjacency check
        H(l_{i-1} || pk || i) == l_i
compares the true continuation of segment s-1 against the reset value H(pk || s) -- these
differ, so the cheater is CAUGHT. Interior challenges (i not a multiple of k) still pass.

Per random challenge, detection probability p1 = (#interior boundaries)/(#indices)
= (N/k - 1)/(N - 1) ~= 1/k. With c independent challenges per round, the round detection
probability is 1 - (1 - p1)^c.

This script (1) VALIDATES the model with the real verify_v2 -- confirms detection happens
exactly on boundary challenges -- and (2) gives the analytic and Monte-Carlo detection
probability for k = 2^4..2^16 and c in {1,10,50,100}, at the thesis size N.

Standalone, fixed seed. Writes results/results_v2_reset.csv.
"""
import csv, random, statistics
from pathlib import Path
import numpy as np
from pospace import H, GAMMA, chain_step, build_tree, node, merkle_path, verify_v2

HERE = Path(__file__).resolve().parent
RES = HERE / "results"; RES.mkdir(exist_ok=True)
SEED = 1
N_THESIS = 3_355_443_200          # 100 GiB / 32 B, the size claimed in the thesis


def seg_start_label(pk, s):
    """Directly computable segment-start value (no stored checkpoint)."""
    return H(pk + s.to_bytes(8, "big"))

def build_fake_reset_leaves(pk, N, k):
    """Fake chain that resets to seg_start_label at every multiple of k."""
    out = bytearray(N * 32)
    for s in range(N // k):
        h = seg_start_label(pk, s)
        base = s * k
        out[32 * base:32 * base + 32] = h
        for t in range(1, k):
            h = chain_step(h, pk, base + t)
            out[32 * (base + t):32 * (base + t) + 32] = h
    return bytes(out)


def validate_model(pk, N, k, rng, n_random=4000, n_boundary=2000):
    """Use the REAL verify_v2 to confirm: boundary challenges are caught, interior pass."""
    leaves = build_fake_reset_leaves(pk, N, k)
    levels = build_tree(leaves)
    root = levels[-1]

    def resp(i):
        out = []
        for j in (i - 1, i):
            out.append((node(levels[0], j), merkle_path(levels, j)))
        return tuple(out)

    # boundaries: i = k, 2k, ... ; all must FAIL
    b_caught = b_total = 0
    for m in range(1, N // k):
        i = m * k
        b_total += 1
        if not verify_v2(root, pk, N, i, resp(i)):
            b_caught += 1
        if b_total >= n_boundary:
            break
    # random challenges: must fail IFF i % k == 0
    consistent = tested = 0
    for _ in range(n_random):
        i = rng.randrange(1, N)
        tested += 1
        passed = verify_v2(root, pk, N, i, resp(i))
        is_boundary = (i % k == 0)
        if passed == (not is_boundary):
            consistent += 1
    return dict(boundary_caught=b_caught, boundary_total=b_total,
                random_consistent=consistent, random_tested=tested)


def run():
    rng = random.Random(SEED)

    # ---- (1) validate the detection model with real verify_v2 (small N) ----
    print("=== model validation (real verify_v2) ===")
    for (logN, logk) in [(16, 6), (18, 8), (14, 4)]:
        pk = bytes(rng.getrandbits(8) for _ in range(33))
        v = validate_model(pk, 2**logN, 2**logk, rng)
        print(f"  N=2^{logN} k=2^{logk}: boundary challenges caught "
              f"{v['boundary_caught']}/{v['boundary_total']}; "
              f"random challenges consistent with 'detected iff i%k==0' "
              f"{v['random_consistent']}/{v['random_tested']}")

    # ---- (2) detection probability table at the thesis size ----
    print("\n=== detection probability (analytic vs Monte-Carlo), N = "
          f"{N_THESIS:,} ===")
    N = N_THESIS
    ks = [2**e for e in range(4, 17)]          # 2^4 .. 2^16
    cs = [1, 10, 50, 100]
    R = 200_000                                 # Monte-Carlo rounds
    mc = np.random.default_rng(SEED)
    rows = []
    for k in ks:
        p1 = (N // k - 1) / (N - 1)             # per-challenge detection probability
        # storage fraction if it keeps only the upper tree (no checkpoints): ~ (2N/k)/(2N)=1/k
        store_frac_upper = (2 * (N // k) - 1) / (2 * N - 1)
        for c in cs:
            p_analytic = 1 - (1 - p1) ** c
            # Monte-Carlo: R rounds of c independent challenges; a round is "caught" if any of
            # the c challenges hits a reset boundary. #hits per round ~ Binomial(c, p1).
            p_sim = float((mc.binomial(c, p1, size=R) > 0).mean())
            rows.append(dict(N=N, log2k=k.bit_length() - 1, k=k,
                             p1_per_challenge=p1, c=c,
                             p_detect_analytic=p_analytic,
                             p_detect_sim=p_sim,
                             expected_rounds_to_detect=(1 / p_analytic if p_analytic > 0 else float("inf")),
                             storage_fraction_upper_only=store_frac_upper))
        print(f"  k=2^{k.bit_length()-1:<2d} (p1={p1:.2e}, store~{store_frac_upper*100:.4f}%): "
              + "  ".join(f"c={c}:{1-(1-p1)**c:.3f}" for c in cs))

    with open(RES / "results_v2_reset.csv", "w", newline="") as f:
        w = csv.DictWriter(f, rows[0].keys()); w.writeheader(); w.writerows(rows)
    print(f"\nWrote results/results_v2_reset.csv ({len(rows)} rows).")
    print("Reading: a cheater who wants, say, <1% chance of being caught over a round of "
          "c=100 challenges needs (1-1/k)^100 > 0.99, i.e. k > ~10000 (k>=2^14). "
          "That large k is exactly what the checkpoint timing budget (Part 4) also forces.")


if __name__ == "__main__":
    run()
