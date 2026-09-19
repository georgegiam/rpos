"""Check 1: does rpos.py's multi-threaded plotting produce N distinct chain hashes?"""
import sys, io, contextlib, importlib.util, hashlib
src = open(__import__('pathlib').Path(__file__).resolve().parent.parent / 'rpos.py').read().split('# Parameters')[0]   # functions only, skip the 1 GiB run
ns = {}; exec(src, ns)
key = hashlib.sha256(b'some_secret_key').hexdigest()
for threads in (1, 2, 4, 8):
    with contextlib.redirect_stdout(io.StringIO()):
        hashes, _ = ns['generate_hashes_in_parallel'](key, 80_000, num_threads=threads)
    print(f"threads={threads}: {len(hashes):,} hashes written, {len(set(hashes)):,} distinct "
          f"({len(set(hashes))/len(hashes):.0%})")
