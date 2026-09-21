# sim/

Phase 5 — the SimPy simulator that reproduces the protocol at large scale (N = 1k–10k), calibrated against and validated by the emulation testbed.

- `chord_sim.py` (#25) — converged Chord ring; analytic routing (`route()`, an exact port of `node/chord.py find_successor`) + a per-hop SimPy timing layer. Pure-Chord hops (matches theory ½·log₂N).
- `query_sim.py` (#26) — the DNS query path (Algorithm 2) on top of that ring: cache → DHT (primary + s replicas, majority vote) → fallback (iterative resolution + store-back), Zipf α=1.0 workload, cold-start warming. Emits per-query hops + latency. Run: `python -m sim.query_sim`. Delay weights are placeholders; numeric calibration to emulation is #29.
