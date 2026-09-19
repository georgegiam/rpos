"""Shared identifier + circular-interval helpers for the Chord ring.

The ring is 160 bits wide. A node's ID is SHA-256(pk) reduced into the ring, and a
chunk's ID is SHA-256(domain) reduced the same way, so nodes and chunks share one
identifier space (this is what lets `find_successor(chunk_id)` name the responsible node).
"""
import hashlib

RING_BITS = 160
RING_SIZE = 1 << RING_BITS          # 2**160


def _sha_int(b: bytes) -> int:
    return int.from_bytes(hashlib.sha256(b).digest(), "big")


def node_id_from_pk(pk: bytes) -> int:
    """Node ID = SHA-256(pk), reduced into the 160-bit ring."""
    return _sha_int(pk) % RING_SIZE


def chunk_id(domain: str) -> int:
    """Chunk ID = SHA-256(domain) mod 2**160."""
    return _sha_int(domain.encode("utf-8")) % RING_SIZE


def in_interval(x: int, a: int, b: int, inc_left: bool = False, inc_right: bool = False) -> bool:
    """True iff x lies in the circular interval between a and b (mod RING_SIZE).

    inc_left/inc_right choose whether the endpoints are included. Handles the wrap
    where a >= b, and the degenerate a == b (whole ring except, or including, the point).
    """
    x %= RING_SIZE
    a %= RING_SIZE
    b %= RING_SIZE
    if a == b:
        # Modular convention: an interval whose endpoints coincide spans the whole ring.
        # Open on both sides excludes only the shared endpoint; otherwise it is everything.
        if not inc_left and not inc_right:
            return x != a
        return True
    if a < b:
        left = a <= x if inc_left else a < x
        right = x <= b if inc_right else x < b
        return left and right
    # wrap-around: (a, RING_SIZE) U [0, b)
    left = a <= x if inc_left else a < x
    right = x <= b if inc_right else x < b
    return left or right
