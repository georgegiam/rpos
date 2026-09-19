"""
Faithful implementation of the thesis PoSpace (Algorithms 4 and 5), plus a
"v2" variant with verifiable leaves, used for the Phase 1 risk check.

Tree layout: levels[0] = leaves (N*32 bytes), levels[-1] = root. N is a power of 2.
Node j of level l is levels[l][32*j : 32*j+32].
"""
import hashlib, os

H = lambda b: hashlib.sha256(b).digest()
GAMMA = b"pospace-gamma"


# ---------- Merkle tree ----------
def build_tree(leaves: bytes):
    levels = [leaves]
    cur = leaves
    while len(cur) > 32:
        cur = b"".join(H(cur[i:i + 64]) for i in range(0, len(cur), 64))
        levels.append(cur)
    return levels

def node(level: bytes, j: int) -> bytes:
    return level[32 * j:32 * j + 32]

def merkle_path(levels, i):
    """Sibling hashes from leaf level up to (not including) the root."""
    path = []
    for lvl in levels[:-1]:
        path.append(node(lvl, i ^ 1))
        i >>= 1
    return path

def root_from_path(leaf, i, path):
    cur = leaf
    for sib in path:
        cur = H(cur + sib) if i % 2 == 0 else H(sib + cur)
        i >>= 1
    return cur


# ---------- v1: the thesis scheme ----------
def plot_v1(k: bytes, N: int) -> bytes:
    """Algorithm 4: h0 = H(gamma||k), hi = H(h_{i-1}||k), with k the PRIVATE key."""
    out = bytearray(N * 32)
    h = H(GAMMA + k)
    out[0:32] = h
    for i in range(1, N):
        h = H(h + k)
        out[32 * i:32 * i + 32] = h
    return bytes(out)

def verify_v1(root, N, i, leaf, path):
    """Algorithm 5 VERIFYCHALLENGE: the Verifier only has root (it cannot recompute
    the leaf, because the leaf depends on the Prover's private key)."""
    return len(path) == N.bit_length() - 1 and root_from_path(leaf, i, path) == root


# ---------- v2: verifiable leaves (chain over the PUBLIC key, adjacency check) ----------
def chain_step(prev: bytes, pk: bytes, i: int) -> bytes:
    return H(prev + pk + i.to_bytes(8, "big"))

def plot_v2(pk: bytes, N: int) -> bytes:
    out = bytearray(N * 32)
    h = H(GAMMA + pk)
    out[0:32] = h
    for i in range(1, N):
        h = chain_step(h, pk, i)
        out[32 * i:32 * i + 32] = h
    return bytes(out)

def verify_v2(root, pk, N, i, resp):
    """Challenge i (1..N-1): prover opens leaves i-1 and i; the verifier checks both
    paths AND that leaf_i = H(leaf_{i-1} || pk || i)."""
    (l_prev, p_prev), (l_cur, p_cur) = resp
    return (verify_v1(root, N, i - 1, l_prev, p_prev)
            and verify_v1(root, N, i, l_cur, p_cur)
            and chain_step(l_prev, pk, i) == l_cur)
