"""Attack 1 on the thesis scheme (v1): claim N leaves of storage while storing only log2(N) hashes.
Because leaves depend on the private key, the Verifier cannot check a leaf's value; it only
checks that the Merkle path hashes up to the committed root. So a cheater can commit to a tree
whose leaves are all the same constant c: every node at a level is identical, so one hash per
level answers every challenge."""
import os, random, time, csv
from pospace import H, plot_v1, build_tree, merkle_path, verify_v1

class ConstantLeafCheater:
    def __init__(self, N, c=b"\x00" * 32):
        self.N = N; self.level_vals = [c]
        for _ in range(N.bit_length() - 1):
            self.level_vals.append(H(self.level_vals[-1] * 2))
        self.root = self.level_vals[-1]
    def storage_bytes(self): return 32 * len(self.level_vals)
    def respond(self, i):   # leaf, path
        return self.level_vals[0], self.level_vals[:-1]

rows = []
rng = random.Random(1)
# (a) side by side with an honest prover at N = 2^20 (32 MiB of leaves)
N = 2**20; k = os.urandom(32)
t = time.time(); levels = build_tree(plot_v1(k, N)); t_plot = time.time() - t
honest_root = levels[-1]
cheat = ConstantLeafCheater(N)
C = 10_000
ok_h = sum(verify_v1(honest_root, N, i, levels[0][32*i:32*i+32], merkle_path(levels, i))
           for i in (rng.randrange(N) for _ in range(C)))
t = time.time()
ok_c = sum(verify_v1(cheat.root, N, i, *cheat.respond(i)) for i in (rng.randrange(N) for _ in range(C)))
t_c = (time.time() - t) / C
print(f"N=2^20  honest: plot+tree {t_plot:.1f}s, stores {sum(map(len, levels))/2**20:.0f} MiB, passed {ok_h}/{C}")
print(f"N=2^20  cheater: stores {cheat.storage_bytes()} bytes, passed {ok_c}/{C}, {t_c*1e6:.0f} µs per response")
# (b) claim ~128 GiB of leaves (N = 2^32), the size used in the thesis
for e in (24, 28, 32, 36):
    N = 2**e; cheat = ConstantLeafCheater(N)
    t = time.time(); ok = sum(verify_v1(cheat.root, N, i, *cheat.respond(i))
                              for i in (rng.randrange(N) for _ in range(C))); dt = (time.time()-t)/C
    claimed = 2 * N * 32  # tree size honest node must keep
    print(f"N=2^{e}: claimed {claimed/2**30:,.1f} GiB, cheater stores {cheat.storage_bytes()} B, passed {ok}/{C}, {dt*1e6:.0f} µs")
    rows.append(dict(log2N=e, claimed_GiB=claimed/2**30, cheater_bytes=cheat.storage_bytes(), passed=ok, challenges=C, resp_us=dt*1e6))
with open("results_attack_v1.csv", "w", newline="") as f:
    w = csv.DictWriter(f, rows[0].keys()); w.writeheader(); w.writerows(rows)
