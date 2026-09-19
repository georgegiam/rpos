"""Fix A, step 1: a depth-robust graph (DRG) via DRSample.

DRSample (Alwen, Blocki, Harsha, "Practical Graphs for Optimal Side-Channel Resistant
Proofs of Space", ACM CCS 2017). For node i > 0:
  * the PATH edge  (i-1, i)  is always present;
  * for each of the (delta-1) extra in-edges, a back-edge (r, i) is sampled by the bucket
    method: pick g uniform in [1, floor(log2 i)+1], then a distance d uniform in
    (2^(g-1), 2^g], and set r = i - d (clamped to >= 0).
This puts the extra parent at a geometrically spread distance, which is what gives the graph
its depth-robustness. The construction is DATA-INDEPENDENT: parents depend only on (i, pk,
delta), never on the labels, so the verifier reconstructs parents(i) itself.

Determinism: all randomness comes from SHA-256(pk || "drg" || i || edge_index), so prover and
verifier agree bit-for-bit, and a run is reproducible from the same pk.

parents(i, pk, delta) -> sorted list of distinct parent indices, all < i.
"""
import hashlib

def _digest(pk: bytes, i: int, j: int) -> bytes:
    return hashlib.sha256(pk + b"drg" + i.to_bytes(8, "big") + j.to_bytes(4, "big")).digest()

def _sample_back_distance(pk: bytes, i: int, j: int) -> int:
    """Bucket method: g ~ U[1, floor(log2 i)+1]; d ~ U(2^(g-1), 2^g]."""
    dig = _digest(pk, i, j)
    L = i.bit_length()                       # floor(log2 i)+1  for i >= 1
    g = 1 + int.from_bytes(dig[0:8], "big") % L
    span = 1 << (g - 1)                       # 2^(g-1)
    d = (1 << (g - 1)) + 1 + int.from_bytes(dig[8:16], "big") % span  # in [2^(g-1)+1, 2^g]
    return d

def parents(i: int, pk: bytes, delta: int) -> list:
    """Distinct parent indices of node i (< i), including the path edge (i-1)."""
    if i == 0:
        return []
    ps = {i - 1}
    for j in range(delta - 1):
        d = _sample_back_distance(pk, i, j)
        ps.add(max(0, i - d))
    return sorted(ps)

def parents_all(N: int, pk: bytes, delta: int):
    """Precompute parents for all nodes once. Returns a list-of-lists, index by node."""
    return [parents(i, pk, delta) for i in range(N)]


# ----------------------------- unit tests -----------------------------
def _test():
    pk = b"\x11" * 33
    N = 1 << 14
    for delta in (2, 4, 8):
        P = parents_all(N, pk, delta)
        # (a) DAG: every parent strictly less than the node
        for i in range(N):
            assert all(0 <= p < i for p in P[i]), (i, P[i])
            assert P[i] == sorted(set(P[i])), "parents must be sorted & distinct"
            if i > 0:
                assert (i - 1) in P[i], "path edge missing"
                assert len(P[i]) <= delta, "in-degree exceeds delta"
        assert P[0] == []
        # (b) reproducible from the same seed
        P2 = parents_all(N, pk, delta)
        assert P == P2, "not reproducible"
        # (c) different pk -> different graph (with overwhelming probability)
        P3 = parents_all(N, b"\x22" * 33, delta)
        if delta > 2:
            assert P != P3, "graph did not depend on pk"
        # in-degree stats
        avg_indeg = sum(len(p) for p in P) / N
        print(f"delta={delta}: N={N}, DAG OK, reproducible OK, avg in-degree {avg_indeg:.3f}")
    print("drg.py: all tests passed")

if __name__ == "__main__":
    _test()
