"""Attack on v2 (verifiable-leaf variant): the CHECKPOINT / time-memory trade-off.

v2 chains over the PUBLIC key so the verifier CAN check leaf values
(leaf_i == H(leaf_{i-1} || pk || i)), which kills the v1 constant-leaf attack. But the
chain is still a plain SEQUENTIAL hash chain, and a sequential chain is not depth-robust:
any label h_j can be regenerated in O(k) steps from a checkpoint stored k positions back.
So a cheater need not keep the leaves at all.

CHEATER:
  * plots the real tree ONCE (it must publish a real root), then DELETES the leaves and the
    lower log2(k) tree levels;
  * keeps only  (a) one chain label per segment start  h_{s*k}   (checkpoints, 32*N/k bytes)
                (b) the Merkle levels from level log2(k) up to the root (~64*N/k bytes).
  On challenge i it recomputes the k-leaf segment(s) containing i-1 and i from the checkpoint
  (~k chain steps), rebuilds that subtree (~k hashes), reads the lower siblings from the
  rebuilt subtree and the upper siblings from the stored levels.

This script measures, for N = 2^20..2^24 and k = 2^4..2^16:
  - storage as a fraction of the honest node's storage (full tree);
  - cheater response time  (measured in-process AND rescaled to the measured C chain rate,
    which is what a native cheater actually achieves; Python is ~20x slower);
  - pass rate against verify_v2;
and compares with the honest prover reading the tree from a real file on disk (uncached
per-node reads), on this machine's SSD.

Standalone, fixed seed. Writes results/results_v2_checkpoint.csv and results/honest_disk.csv.
"""
import csv, os, sys, time, random, fcntl, statistics
from pathlib import Path
from pospace import (H, GAMMA, chain_step, plot_v2, build_tree, node,
                     merkle_path, root_from_path, verify_v2)

HERE = Path(__file__).resolve().parent
RES = HERE / "results"; RES.mkdir(exist_ok=True)
SEED = 1
F_NOCACHE = 48  # macOS fcntl: bypass the unified buffer cache for this fd

# --- measured single-core native SHA-256 chain rate (from chainrate/measure_env) ---
def load_chain_rate(default_mhs=20.36):
    p = RES / "chainrate.csv"
    if p.exists():
        for r in csv.reader(open(p)):
            if r and r[0] == "median":
                return float(r[1]) * 1e6
    return default_mhs * 1e6
CHAIN_RATE = load_chain_rate()   # hashes / second, native single core


# ============================ honest prover (on disk) ============================
def honest_full_tree_bytes(N):
    return 32 * (2 * N - 1)   # all levels, leaf..root

def write_tree_to_disk(levels, path):
    """Concatenate levels [leaves..root] into one file; return byte offset of each level."""
    offsets, off = [], 0
    with open(path, "wb") as f:
        for lvl in levels:
            offsets.append(off)
            f.write(lvl); off += len(lvl)
    return offsets

def honest_disk_response(fd, offsets, logN, i):
    """Real per-node reads: read leaves i-1, i and every sibling on both Merkle paths.
    Returns nothing (we only time it); reads are uncached (F_NOCACHE) => true SSD reads."""
    for leaf_idx in (i - 1, i):
        os.pread(fd, 32, offsets[0] + 32 * leaf_idx)      # the leaf
        j = leaf_idx
        for l in range(logN):                              # one sibling per level
            os.pread(fd, 32, offsets[l] + 32 * (j ^ 1))
            j >>= 1


# ============================ checkpoint cheater ============================
class CheckpointCheater:
    def __init__(self, pk, N, k, leaves=None, levels=None):
        assert N & (N - 1) == 0 and k & (k - 1) == 0 and k <= N
        self.pk, self.N, self.k = pk, N, k
        self.logk = k.bit_length() - 1
        self.logN = N.bit_length() - 1
        if leaves is None:                  # one-time honest plot (unless caller supplies it)
            leaves = plot_v2(pk, N)
        if levels is None:
            levels = build_tree(leaves)
        # (a) checkpoints: chain label at the start of every segment, h_{s*k}
        self.checkpoints = [bytes(leaves[32 * (s * k):32 * (s * k) + 32])
                            for s in range(N // k)]
        # (b) stored upper tree: levels[logk .. root]
        self.upper = [bytes(l) for l in levels[self.logk:]]
        self.root = levels[-1]              # cheater keeps only checkpoints + upper levels

    def storage_bytes(self):
        return 32 * len(self.checkpoints) + sum(len(l) for l in self.upper)

    def _rebuild_segment(self, s):
        """Recompute the k leaves of segment s from its checkpoint and build its subtree.
        Returns (sub_levels, nhash) where nhash is the SHA-256 work done."""
        k, pk = self.k, self.pk
        start = s * k
        buf = bytearray(k * 32)
        h = self.checkpoints[s]
        buf[0:32] = h
        for t in range(1, k):
            h = chain_step(h, pk, start + t)
            buf[32 * t:32 * t + 32] = h
        sub = build_tree(bytes(buf))
        nhash = (k - 1) + (k - 1)           # k-1 chain steps + k-1 subtree hashes
        return sub, nhash

    def respond(self, i):
        """Answer challenge i: open leaves i-1 and i with full Merkle paths."""
        nhash = 0
        seg_cache = {}
        resp = []
        for j in (i - 1, i):
            s = j >> self.logk
            if s not in seg_cache:
                seg_cache[s], nh = self._rebuild_segment(s)
                nhash += nh
            sub = seg_cache[s]
            local = j & (self.k - 1)
            lower = merkle_path(sub, local)                 # siblings, levels 0..logk-1
            upper = merkle_path(self.upper, s)              # siblings, levels logk..root-1
            leaf = node(sub[0], local)
            resp.append((leaf, lower + upper))
        return tuple(resp), nhash


def run():
    rng = random.Random(SEED)
    Ns = [2**e for e in (20, 21, 22, 23, 24)]
    ks = [2**e for e in (4, 6, 8, 10, 12, 14, 16)]
    # adaptive challenge count: bound in-process hash work to ~4M hashes per config,
    # but always >= 20 (the attack is deterministic, so 20 already pins the pass rate).
    def n_chal(k):
        return max(20, min(200, 2_000_000 // (2 * k)))

    cheat_rows, honest_rows = [], []

    for N in Ns:
        logN = N.bit_length() - 1
        pk = bytes(rng.getrandbits(8) for _ in range(33))   # 33-byte compressed pubkey

        # ---- honest baseline: write real tree to disk, time uncached per-node reads ----
        leaves = plot_v2(pk, N)
        levels = build_tree(leaves)
        root = levels[-1]
        tree_path = HERE / f"_tree_N{logN}.bin"
        offsets = write_tree_to_disk(levels, tree_path)
        tree_MiB = os.path.getsize(tree_path) / 2**20
        fd = os.open(tree_path, os.O_RDONLY)
        try:
            fcntl.fcntl(fd, F_NOCACHE, 1)
        except OSError:
            pass
        times = []
        for _ in range(200):                                # honest reads are cheap: 200 reps
            i = rng.randrange(1, N)
            t0 = time.perf_counter()
            honest_disk_response(fd, offsets, logN, i)
            times.append(time.perf_counter() - t0)
        os.close(fd)
        os.unlink(tree_path)                                # delete immediately (disk budget)
        honest_med = statistics.median(times)
        honest_store = honest_full_tree_bytes(N)
        honest_rows.append(dict(log2N=logN, N=N, tree_MiB=round(tree_MiB, 1),
                                honest_store_bytes=honest_store,
                                honest_disk_resp_s=honest_med,
                                reads_per_resp=2 * (logN + 1)))
        print(f"[honest] N=2^{logN}: tree {tree_MiB:6.1f} MiB on SSD, "
              f"uncached disk response {honest_med*1e3:7.3f} ms "
              f"({2*(logN+1)} reads)")

        # ---- cheater: for each k ----
        for k in ks:
            if k > N:
                continue
            cheat = CheckpointCheater(pk, N, k, leaves=leaves, levels=levels)
            assert cheat.root == root, "cheater must publish the real root"
            C = n_chal(k)
            # pass rate
            passed = 0
            for _ in range(C):
                i = rng.randrange(1, N)
                resp, _ = cheat.respond(i)
                if verify_v2(cheat.root, pk, N, i, resp):
                    passed += 1
            # timing + worst-case hash work
            times, nhashes = [], []
            for _ in range(C):
                i = rng.randrange(1, N)
                t0 = time.perf_counter()
                _, nh = cheat.respond(i)
                times.append(time.perf_counter() - t0)
                nhashes.append(nh)
            py_med = statistics.median(times)
            nh_max = max(nhashes)
            t_at_crate = nh_max / CHAIN_RATE
            frac = cheat.storage_bytes() / honest_store
            cheat_rows.append(dict(
                log2N=logN, N=N, log2k=k.bit_length() - 1, k=k,
                storage_bytes=cheat.storage_bytes(),
                honest_store_bytes=honest_store,
                storage_fraction=frac,
                nhash_worst=nh_max,
                cheat_resp_py_s=py_med,
                cheat_resp_at_crate_s=t_at_crate,
                honest_disk_resp_s=honest_med,
                pass_rate=passed / C,
                challenges=C))
            print(f"  [cheat] N=2^{logN} k=2^{k.bit_length()-1:<2d}: "
                  f"store {frac*100:6.3f}% of honest, "
                  f"pass {passed}/{C}, "
                  f"resp@Crate {t_at_crate*1e3:7.3f} ms "
                  f"(worst {nh_max} hashes), py {py_med*1e3:.2f} ms")

    with open(RES / "results_v2_checkpoint.csv", "w", newline="") as f:
        w = csv.DictWriter(f, cheat_rows[0].keys()); w.writeheader(); w.writerows(cheat_rows)
    with open(RES / "honest_disk.csv", "w", newline="") as f:
        w = csv.DictWriter(f, honest_rows[0].keys()); w.writeheader(); w.writerows(honest_rows)
    print(f"\nWrote results/results_v2_checkpoint.csv ({len(cheat_rows)} rows) "
          f"and results/honest_disk.csv ({len(honest_rows)} rows).")
    print(f"(chain rate used for @Crate columns: {CHAIN_RATE/1e6:.2f} MH/s)")


if __name__ == "__main__":
    run()
