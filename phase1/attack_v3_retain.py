"""Attack on v3 (DRG labelling): the RETENTION time-memory trade-off, re-run vs v2.

v2 chains labels over a *path graph* (l_i depends only on l_{i-1}), so a cheater who keeps one
checkpoint every k positions regenerates any label in O(k) steps -- the ~1.5/k checkpoint attack
(attack_v2_checkpoint.py). Fix A replaces the chain with a DRSample **depth-robust graph**
(drg.py): l_i now depends on ALL of node i's DRG parents (pospace_drg.py). This script runs the
SAME attack class against v3 and shows the trade-off collapses.

CHEATER (retention attack, same accounting as attack_v2_checkpoint.py):
  * plots the real DRG-labelled tree ONCE (must publish the real root), then keeps only
      (a) a fraction rho of the labels -- every s-th label, s = 1/rho  (32*N*rho bytes), and
      (b) the upper Merkle levels  levels[log2 s ..]  (~64*N*rho bytes);
    discards every other label and the lower log2(s) tree levels.
  * a v3 challenge i opens node i AND all its DRG parents, each with a Merkle path. To answer,
    the cheater must MATERIALISE those labels. A discarded label l_j is not one chain step from a
    checkpoint: recomputing it means recomputing its whole **back-cone** -- follow DRG parents
    back until every dependency bottoms out at a retained label -- and, because the graph is
    depth-robust, that back-cone is large in SIZE (total hashes) and in CRITICAL-PATH DEPTH
    (sequential work even with unlimited cores). That is exactly the property Fix A buys.

For each config (N, delta, rho) this measures, over random challenges:
  - storage fraction of the honest full tree (directly comparable to the v2 column);
  - recompute hashes / challenge  (back-cone label recomputes + lower-subtree rebuild), median & p99;
  - critical-path depth (back-cone depth), median & p99;
  - response time @ the measured 20.36 MH/s native rate, BOTH sequential (total hashes / rate)
    and the parallel floor (critical-path depth / rate);
  - pass rate against verify_v3 (1.0 by construction; validated by real reconstruction where cheap).

Counts are structural and deterministic, so the sweep computes them by graph traversal (fast,
vectorised) without hashing; a bounded subset is reconstructed for real and checked with verify_v3.

Standalone, fixed seed. Writes results/results_v3_retain.csv and prints the v2-vs-v3 money table
(reads results/results_v2_checkpoint.csv). The comparison FIGURE lives in plots.py (issue #6).
"""
import csv, statistics
from pathlib import Path
import numpy as np

from pospace import build_tree, node, merkle_path
from pospace_drg import plot_v3, commit_v3, verify_v3, _label
from drg import parents

HERE = Path(__file__).resolve().parent
RES = HERE / "results"; RES.mkdir(exist_ok=True)
SEED = 1

# sweep (issue #3)
NS = [2**18, 2**20, 2**22]
DELTAS = [2, 4, 8]
RHO_EXPS = list(range(0, 11))            # rho = 2^-r, r=0..10  -> rho in {1, 1/2, ..., 1/1024}

# per-config budgets (keep Python-side work bounded; counts stay exact regardless)
def metric_challenges(N):                 # fewer samples at large N (saturated & low-variance)
    return 20 if N >= 2**22 else 40 if N >= 2**20 else 60
DEPTH_BUDGET = 300_000                    # compute exact critical-path depth only up to this
                                         # back-cone size; beyond it the config is "saturated"
                                         # (recompute ~ full replot) and depth is reported as -1
VERIFY_MAX_N = 2**20                      # actually plot + reconstruct + verify_v3 at/below this N
VERIFY_CHALLENGES = 5                     # real round-trip checks per verifiable config
VERIFY_CLOSURE_CAP = 200_000             # skip real recompute if a challenge's back-cone exceeds it


# --- measured single-core native SHA-256 rate (shared with attack_v2_checkpoint.py) ---
def load_chain_rate(default_mhs=20.36):
    p = RES / "chainrate.csv"
    if p.exists():
        for r in csv.reader(open(p)):
            if r and r[0] == "median":
                return float(r[1]) * 1e6
    return default_mhs * 1e6
CHAIN_RATE = load_chain_rate()           # hashes / second, native single core


def pct(xs, q):
    """Simple nearest-rank percentile (q in [0,1]); xs need not be sorted."""
    if not xs:
        return float("nan")
    s = sorted(xs)
    k = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return s[k]


# ============================ DRG graph as a padded parent table ============================
def parent_table(N, pk, delta):
    """Row i = the parents of node i, sorted, padded to width delta with -1.

    Built once per (N, delta) and reused across all rho (rho only changes which labels are
    retained, not the graph). Lets the back-cone traversal be pure array lookups.
    """
    tab = np.full((N, delta), -1, dtype=np.int64)
    for i in range(N):
        ps = parents(i, pk, delta)
        tab[i, :len(ps)] = ps
    return tab


# ============================ storage accounting (mirrors v2) ============================
def storage_bytes(N, s):
    """Retained labels (N/s of them) + upper Merkle levels levels[log2 s ..].

    For s==1 the retained labels ARE the whole leaf level, so the upper part starts at level 1
    (no double count); the fraction is then 1.0 (keep everything).
    """
    logN = N.bit_length() - 1
    logs = s.bit_length() - 1
    upper_start = max(logs, 1)
    retained = 32 * (N // s)
    upper = 32 * sum(N >> l for l in range(upper_start, logN + 1))
    return retained + upper

def honest_bytes(N):
    return 32 * (2 * N - 1)               # full tree, leaves..root


# ============================ back-cone: size (vectorised) & depth ============================
def block_leaves(opened, s):
    """The stride-aligned blocks (each s leaves) that must be rebuilt to open `opened`.

    Returns (blocks, base_targets): the distinct block ids, and every leaf index inside them.
    Opening a node needs its lower Merkle siblings, i.e. its whole block's subtree.
    """
    blocks = sorted({o // s for o in opened})
    base = np.concatenate([np.arange(b * s, b * s + s, dtype=np.int64) for b in blocks]) \
        if blocks else np.empty(0, dtype=np.int64)
    return blocks, base

def backcone_mask(base_targets, retained_mask, tab):
    """Vectorised BFS closure: all MISSING nodes that must be recomputed to know base_targets.

    Frontier-based over the padded parent table; retained nodes bottom out. Converges in a few
    rounds even for O(N) closures because DRG back-edges jump geometrically far (small hop
    diameter). Returns a boolean mask over [0, N).
    """
    N = retained_mask.shape[0]
    seen = np.zeros(N, dtype=bool)
    frontier = base_targets[~retained_mask[base_targets]]
    frontier = np.unique(frontier)
    seen[frontier] = True
    while frontier.size:
        par = tab[frontier].ravel()
        par = par[par >= 0]
        par = par[~retained_mask[par]]
        par = par[~seen[par]]
        frontier = np.unique(par)
        seen[frontier] = True
    return seen

def backcone_depth(seen, tab):
    """Longest recompute chain over the back-cone (critical path, in hashes).

    depth[j] = 1 + max(depth[p] over missing parents p); retained parents contribute 0.
    np.nonzero yields indices in ascending order == a valid topological order (parents < child),
    so a single forward pass suffices. Only called when |seen| <= DEPTH_BUDGET.
    """
    idxs = np.nonzero(seen)[0]
    depth = {}
    best = 0
    for j in idxs:
        d = 0
        for p in tab[j]:
            if p < 0:
                break
            dp = depth.get(int(p))
            if dp is not None and dp > d:
                d = dp
        d += 1
        depth[int(j)] = d
        if d > best:
            best = d
    return best


# ============================ one config: metrics by traversal ============================
def measure_config(N, delta, s, tab, rng, n_chal):
    """Sample challenges; return per-challenge recompute-hash counts and critical-path depths."""
    logs = s.bit_length() - 1
    retained_mask = np.zeros(N, dtype=bool)
    retained_mask[np.arange(0, N, s)] = True

    rec_hashes, depths = [], []
    saturated = False
    for _ in range(n_chal):
        i = rng.randrange(1, N)
        opened = [i] + parents(i, PK, delta)
        blocks, base = block_leaves(opened, s)
        seen = backcone_mask(base, retained_mask, tab)
        n_labels = int(seen.sum())
        n_merkle = len(blocks) * (s - 1)               # rebuild each block's lower subtree
        rec_hashes.append(n_labels + n_merkle)
        if n_labels <= DEPTH_BUDGET:
            depths.append(backcone_depth(seen, tab) + logs)   # + log2(s) subtree levels
        else:
            saturated = True
    return rec_hashes, depths, saturated


# ============================ real reconstruction + verify_v3 (bounded) ============================
def validate_config(N, delta, s, tab, levels, retained_labels, rng):
    """Actually recompute opened labels from the retained set and check with verify_v3.

    Returns (passes, trials). Uses no ground-truth labels except the retained ones -- this is the
    cheater literally executing the attack. Skips challenges whose back-cone exceeds the cap.
    """
    logs = s.bit_length() - 1
    upper = levels[logs:]                               # stored upper Merkle levels
    root = levels[-1]
    retained_mask = np.zeros(N, dtype=bool)
    retained_mask[np.arange(0, N, s)] = True

    passes = trials = 0
    for _ in range(VERIFY_CHALLENGES):
        i = rng.randrange(1, N)
        opened = [i] + parents(i, PK, delta)
        blocks, base = block_leaves(opened, s)
        seen = backcone_mask(base, retained_mask, tab)
        if int(seen.sum()) > VERIFY_CLOSURE_CAP:
            continue
        # recompute every missing label in topological (ascending) order
        known = dict(retained_labels)
        for j in np.nonzero(seen)[0]:
            ps = [int(p) for p in tab[j] if p >= 0]
            known[int(j)] = _label(PK, int(j), [known[p] for p in ps])
        # rebuild each opened node's block subtree to get its lower Merkle path
        subcache = {}
        for b in blocks:
            buf = bytearray(s * 32)
            for t in range(s):
                buf[32 * t:32 * t + 32] = known[b * s + t]
            subcache[b] = build_tree(bytes(buf))
        proof = {}
        for o in opened:
            b, local = o // s, o % s
            sub = subcache[b]
            lower = merkle_path(sub, local)            # levels 0..logs-1
            up = merkle_path(upper, b)                 # levels logs..root-1
            proof[o] = (node(sub[0], local), lower + up)
        trials += 1
        passes += bool(verify_v3(root, PK, N, delta, i, proof))
    return passes, trials


# ============================ driver ============================
PK = b""   # set per (N) in run()

def run():
    global PK
    import random
    rng = random.Random(SEED)
    rows = []

    for N in NS:
        logN = N.bit_length() - 1
        PK = bytes(rng.getrandbits(8) for _ in range(33))     # 33-byte compressed pubkey
        hon = honest_bytes(N)
        for delta in DELTAS:
            print(f"[table] building DRG parent table N=2^{logN} delta={delta} ...", flush=True)
            tab = parent_table(N, PK, delta)
            # plot once for the verifiable N (needed for real verify_v3); large N: metrics only
            levels = None
            if N <= VERIFY_MAX_N:
                labels = plot_v3(PK, N, delta)
                levels, _ = commit_v3(labels)

            for r in RHO_EXPS:
                s = 1 << r
                rho = 1.0 / s
                sb = storage_bytes(N, s)
                frac = sb / hon

                nchal = metric_challenges(N)
                rec, dep, sat = measure_config(N, delta, s, tab, rng, nchal)
                rec_med, rec_p99 = int(statistics.median(rec)), pct(rec, 0.99)
                dep_med = int(statistics.median(dep)) if dep else -1
                dep_p99 = pct(dep, 0.99) if dep else -1

                # pass rate: real reconstruction where cheap, else 1.0 by construction
                pass_validated = 0
                pass_rate = 1.0
                if levels is not None and s >= 2:
                    ret_labels = {int(m): node(levels[0], int(m)) for m in range(0, N, s)}
                    passes, trials = validate_config(N, delta, s, tab, levels, ret_labels, rng)
                    if trials:
                        pass_rate = passes / trials
                        pass_validated = 1

                rows.append(dict(
                    log2N=logN, N=N, delta=delta, log2s=r, s=s, rho=rho,
                    storage_bytes=sb, honest_bytes=hon, storage_fraction=frac,
                    rec_hashes_median=rec_med, rec_hashes_p99=rec_p99,
                    depth_median=dep_med, depth_p99=dep_p99, saturated=int(sat),
                    resp_seq_s_median=rec_med / CHAIN_RATE,
                    resp_seq_s_p99=rec_p99 / CHAIN_RATE,
                    resp_par_s_median=(dep_med / CHAIN_RATE) if dep_med >= 0 else -1,
                    resp_par_s_p99=(dep_p99 / CHAIN_RATE) if dep_p99 >= 0 else -1,
                    pass_rate=pass_rate, pass_validated=pass_validated,
                    challenges=nchal))
                dtxt = f"{dep_med}" if dep_med >= 0 else "SAT"
                print(f"  N=2^{logN} d={delta} rho=1/{s:<4d}: "
                      f"store {frac*100:7.3f}% | rec {rec_med:>9d} h (p99 {rec_p99}) | "
                      f"depth {dtxt:>7} | seq {rec_med/CHAIN_RATE*1e3:9.3f} ms | "
                      f"pass {pass_rate:.2f}{'*' if pass_validated else ''}", flush=True)

    with open(RES / "results_v3_retain.csv", "w", newline="") as f:
        w = csv.DictWriter(f, rows[0].keys()); w.writeheader(); w.writerows(rows)
    print(f"\nWrote results/results_v3_retain.csv ({len(rows)} rows). "
          f"(rate for @Crate columns: {CHAIN_RATE/1e6:.2f} MH/s; * = pass rate verified by "
          f"real reconstruction)")

    money_comparison(rows)


# ============================ v2-vs-v3 money comparison ============================
def money_comparison(v3_rows):
    """Join v2 (chain) and v3 (DRG) at matching storage fraction (k == s) and print the table.

    v2's recompute cost is ~1.5/k storage for O(k) work, flat in N; v3's is the same storage for
    a back-cone that climbs toward O(N). Same axes -> the trade-off Fix A closes. Figure: plots.py.
    """
    v2_path = RES / "results_v2_checkpoint.csv"
    if not v2_path.exists():
        print("\n[money] results_v2_checkpoint.csv not found -- run attack_v2_checkpoint.py first.")
        return
    v2 = list(csv.DictReader(open(v2_path)))
    # index v2 by (log2N, k)
    v2idx = {(int(r["log2N"]), int(r["k"])): r for r in v2}

    print("\n================= money comparison: v2 chain vs v3 DRG (same storage) =================")
    print(f"{'N':>5} {'store%':>8} {'k=s':>6} | {'v2 hashes':>10} {'v2 resp':>10} | "
          f"{'v3 hashes':>11} {'v3 depth':>9} {'v3 resp':>10} | {'v3/v2':>8}")
    print("-" * 92)
    for row in v3_rows:
        key = (row["log2N"], row["s"])
        if key not in v2idx or row["s"] < 2:
            continue
        v2r = v2idx[key]
        v2h = int(v2r["nhash_worst"])
        v2t = float(v2r["cheat_resp_at_crate_s"])
        v3h = row["rec_hashes_median"]
        v3d = row["depth_median"]
        v3t = row["resp_seq_s_median"]
        ratio = v3h / v2h if v2h else float("inf")
        dtxt = f"{v3d}" if v3d >= 0 else "SAT"
        print(f"2^{row['log2N']:<3d} {row['storage_fraction']*100:7.3f}% {row['s']:>6} | "
              f"{v2h:>10d} {v2t*1e3:>8.3f}ms | {v3h:>11d} {dtxt:>9} {v3t*1e3:>8.3f}ms | "
              f"{ratio:>7.0f}x")
    print("-" * 92)
    print("v2: O(k) recompute, flat in N (the ~1.5/k checkpoint trade-off).")
    print("v3: back-cone climbs toward O(N) at the SAME storage -> no cheap trade-off (Fix A).")


if __name__ == "__main__":
    run()
