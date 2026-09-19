"""Fix A, step 2: the DRG-labelled PoSpace scheme (v3).

Same shape as v2 (Merkle commitment over N labels, challenge opens nodes with Merkle paths),
but the label of node i now depends on ALL of its depth-robust-graph parents, not just i-1:

    l_0 = H(pk || 0)
    l_i = H(pk || i || l_{p1} || l_{p2} || ... )   for p in parents(i, pk, delta), in order

A challenge i opens l_i AND every parent label l_p, each with its Merkle path to the root.
The verifier reconstructs parents(i) itself (data-independent), checks every Merkle path, and
checks l_i == H(pk || i || concat of the opened parent labels). Faking a single label now
requires faking its whole parent set, whose labels are themselves committed -- so the only way
to answer is to hold or recompute the real labels. Recomputing is expensive *because* the
graph is depth-robust (that is the whole point of Fix A; see attack_v3_retain.py).

Reuses the Merkle primitives in pospace.py (build_tree, merkle_path, root_from_path).
Standalone; run directly for the round-trip test at N=2^16.
"""
import hashlib
from pospace import H, build_tree, node, merkle_path, root_from_path
from drg import parents, parents_all

GAMMA_TAG = b""  # v3 mixes pk and index directly; no separate gamma needed


def _label(pk: bytes, i: int, parent_labels: list) -> bytes:
    return H(pk + i.to_bytes(8, "big") + b"".join(parent_labels))


# ---------------- plotting & commitment ----------------
def plot_v3(pk: bytes, N: int, delta: int) -> bytes:
    """Label the DRG in topological (index) order. Returns the N*32-byte label array."""
    P = parents_all(N, pk, delta)
    out = bytearray(N * 32)
    out[0:32] = _label(pk, 0, [])
    for i in range(1, N):
        plabels = [out[32 * p:32 * p + 32] for p in P[i]]
        out[32 * i:32 * i + 32] = _label(pk, i, plabels)
    return bytes(out)

def commit_v3(labels: bytes):
    """Merkle-commit the labels. Returns (levels, root)."""
    levels = build_tree(labels)
    return levels, levels[-1]


# ---------------- prove & verify ----------------
def prove_v3(levels, pk: bytes, N: int, delta: int, i: int) -> dict:
    """Open node i and all its parents, each with a Merkle path. Returns {idx: (label, path)}."""
    leaves = levels[0]
    idxs = [i] + parents(i, pk, delta)
    proof = {}
    for idx in idxs:
        proof[idx] = (node(leaves, idx), merkle_path(levels, idx))
    return proof

def verify_v3(root: bytes, pk: bytes, N: int, delta: int, i: int, proof: dict) -> bool:
    """Check every Merkle path against root AND the DRG label equation for node i."""
    plen = N.bit_length() - 1
    ps = parents(i, pk, delta)
    # proof must contain exactly node i and its parents
    if set(proof.keys()) != set([i] + ps):
        return False
    # every opened label must sit at its committed position
    for idx, (label, path) in proof.items():
        if len(path) != plen or root_from_path(label, idx, path) != root:
            return False
    # the label equation: l_i == H(pk || i || concat parent labels in parent order)
    parent_labels = [proof[p][0] for p in ps]        # ps is sorted == plot order
    return proof[i][0] == _label(pk, i, parent_labels)


# ---------------- round-trip test ----------------
def _test():
    import os, random
    rng = random.Random(1)
    pk = bytes(rng.getrandbits(8) for _ in range(33))
    N = 1 << 16
    for delta in (2, 4, 8):
        labels = plot_v3(pk, N, delta)
        levels, root = commit_v3(labels)
        ok = bad_tamper = 0
        C = 500
        for _ in range(C):
            i = rng.randrange(1, N)
            proof = prove_v3(levels, pk, N, delta, i)
            ok += verify_v3(root, pk, N, delta, i, proof)
            # negative control: tamper one parent label -> must fail
            ps = parents(i, pk, delta)
            tp = dict(proof)
            p0 = ps[0]
            tp[p0] = (bytes(a ^ 1 for a in tp[p0][0]), tp[p0][1])
            bad_tamper += (verify_v3(root, pk, N, delta, i, tp) is False)
        # also test node 1 (edge case: single parent 0) and a boundary
        for i in (1, 2, N - 1):
            proof = prove_v3(levels, pk, N, delta, i)
            ok_edge = verify_v3(root, pk, N, delta, i, proof)
            assert ok_edge, f"edge challenge {i} failed"
        print(f"delta={delta}: honest verify {ok}/{C}, tamper rejected {bad_tamper}/{C}, "
              f"edges ok, proof opens {1+len(parents(N-1,pk,delta))} nodes")
        assert ok == C and bad_tamper == C
    print("pospace_drg.py: round-trip + tamper tests passed")

if __name__ == "__main__":
    _test()
