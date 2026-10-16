#!/usr/bin/env python3
"""Issue #46 [B5] — Sybil vs PoSpace admission (Phase 7, examiner point (ii)).

B5 answers the question the whole admission scheme exists to answer: for a fixed STORAGE BUDGET,
how many v3-DRG PoSpace identities can an adversary create, and what fraction of the chunk space
does that buy? And does PoSpace actually RAISE the Sybil cost?

The spine is one relation the codebase already fixes. A v3 plot is laid out as `bytearray(N*32)`
(phase1/pospace_drg.py::plot_v3), so ONE admitted identity costs exactly `32 * N_plot` bytes of
labels. At the thesis plot `REAL_PLOT_N = 3,355,443,200` leaves that is 100 GiB of labels (~200 GiB
if the Merkle tree is retained). Plot storage is LINEAR in plot size and INDEPENDENT of the DRG
in-degree delta (delta changes only plotting TIME and proof SIZE -- FIX_A.md). Admission binds
pk <-> plot <-> id (node_id = SHA-256(pk); the challenger rejects any node where
node_id_from_pk(pk) != peer_id, and the plot is keyed by pk), and a plot cannot be amortised across
identities: k identities need k distinct pks -> k distinct plots. So:

    #identities = floor(storage_budget / (32 * N_plot))

and the examiner-facing headline is: WITHOUT admission a budget buys ~unbounded identities (an
identity is just a keypair, ~33 bytes -> f -> 1 -> full chunk control); WITH v3-DRG PoSpace every
identity is pinned to a real ~100 GiB plot, so a realistic budget buys a VANISHING fraction of an
internet-scale ring. PoSpace raises the per-identity cost by ~ (32*N_plot)/|pk| ~= 3.25e9x.

Chunk control, given m Sybil identities ADDED to a ring of N_honest honest nodes (f = m/(m+N)):
  * primary-arc fraction   ~= m/(m+N)            (share of the ring owned as primary)
  * forge / >=1-of-s       = 1-(1-f)^s           (B1's measured achievable bound)
  * majority capture       = 3 f^2 - 2 f^3  (s=3) (the intended majority-vote bound)
all computed with b1_placement's exact helpers so B5 is consistent with B1/B2.

WHY A MICROBENCHMARK, NOT THE DOCKER TESTBED (mirrors A7/B2): "identities per GB" and "chunk
control" are pure, verifier-reproducible computations over the frozen parameters; a Docker ring adds
nothing and cannot represent a 100 GiB plot. B5 reuses the exact host-side converged-ring + replica
toolkit from experiments/b1_placement.py (the model the node, the sims, B1, B2 and B4 share) and
node/ids.py, so every number is bit-for-bit reconstructible from (N_plot, N_honest, s, seed).

Blocks + an honest control:
  * sybil_yield     -- identities vs storage budget at the thesis plot (and a test-plot row to show
                       the emulation scale is deliberately NOT the security scale); native plot time.
  * chunk_control   -- f and the three control fractions vs budget, analytic at N_honest in
                       {32, 1e3, 1e6}, PLUS a MEASURED N_honest=32 structural anchor over the real
                       converged ring (random Sybil placement), source=real_ring.
  * pospace_vs_free -- the headline: identities & control WITHOUT admission (pk-only, ~33 B) vs WITH
                       v3-DRG PoSpace (100 GiB/identity). Quantifies "PoSpace raises the cost".
  * admission_demo  -- on a REAL in-process PoSpace ring (A7 pattern), admit k distinct Sybils and
                       show each built its OWN plot (k distinct roots) and the pk<->id binding blocks
                       plot reuse -> the NO-AMORTISATION property, B5's tie to Table 4.2 "Amortisation".
  * control         -- honest zero budget -> 0 identities -> structural capture 0 (adversary-caused;
                       a protocol/design property -- admission binds pk<->plot<->id -- NOT chord.py
                       reference-impl fragility).

New code in a new file (CLAUDE.md §2): imports/reads only. rpos/rpos.py, node/chord.py,
node/storage.py, node/ledger.py, node/pospace_admission.py, node/net.py, phase1/pospace_drg.py,
phase1/drg.py and experiments/b1_placement.py stay byte-identical. Fixed seed 20260919.

Run:  python3 experiments/b5_sybil.py                 # full analysis -> CSV + PNG + stdout
      python3 experiments/b5_sybil.py --no-plot       # table only
      python3 experiments/b5_sybil.py --no-demo       # skip the in-process admission demo
      python3 experiments/b5_sybil.py --self-test     # deterministic checks, no Docker
      python3 experiments/b5_sybil.py --budgets 100GiB,1TiB   # quick budget subset
"""
from __future__ import annotations

import argparse
import csv
import math
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
RESULTS = REPO_ROOT / "results"
OUT_CSV = RESULTS / "B5_sybil.csv"
OUT_FIG = RESULTS / "fig_B5_sybil.png"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# host-safe imports (hashlib / sim only -- NO dnspython, NO matplotlib at import time) ----------
from node.ids import node_id_from_pk, chunk_id, RING_SIZE  # noqa: E402
import b1_placement as b1                                   # noqa: E402

# frozen B5 workload (PARAMETERS.md) -----------------------------------------------------------
SEED = 20260919                     # frozen repo seed (CLAUDE.md §2)
DEFAULT_S = 3                       # replication factor
REAL_PLOT_N = 3_355_443_200         # thesis plot (node/pospace_admission.REAL_PLOT_N): ~100 GiB labels
TEST_PLOT_N = 1 << 10               # emulation test plot (node/pospace_admission.PLOT_N): 32 KiB
LABEL_BYTES = 32                    # one label = one SHA-256 digest
PK_BYTES = 33                       # a "free" (no-PoSpace) identity artifact: one public key
EMULATION_N = 32                    # emulation ceiling -> the measured structural anchor ring
DEFAULT_HONEST = [32, 1_000, 1_000_000]            # honest ring sizes for the analytic control curves
FREE_REF_HONEST = 1_000_000                        # internet-ish reference ring for pospace_vs_free
# measured anchor: m Sybils ADDED to a 32-node honest ring (random _pk_for placement, node 0 honest)
ANCHOR_MS = [0, 1, 2, 3, 6, 10, 16, 24, 31]

GIB = 1 << 30
DEFAULT_BUDGETS = ["100GiB", "1TiB", "10TiB", "100TiB", "1PiB", "10PiB", "100PiB"]
DEMO_HONEST_N = 8                   # in-process honest PoSpace ring (the A7 ring)
DEMO_SYBILS = 3                     # distinct Sybils to admit in the demo
DEMO_PLOT_N = 1 << 10              # test plot (cheap; plot COST is quantified by A7)

# Native single-core plot-time floor @ 100 GiB, by DRG in-degree delta (phase1/FIX_A.md §4,
# "Plotting @ 100 GiB"): measured native floor. delta=2 is the node default -> the headline.
PLOT_NATIVE_S_PER_100GIB = {2: 165.0, 4: 247.0, 8: 411.0}
DEFAULT_DELTA = 2


# --- unit helpers -----------------------------------------------------------------------------
_UNITS = [("EiB", 1 << 60), ("PiB", 1 << 50), ("TiB", 1 << 40), ("GiB", 1 << 30),
          ("MiB", 1 << 20), ("KiB", 1 << 10), ("B", 1)]
_SUFFIX = {"eib": 1 << 60, "pib": 1 << 50, "tib": 1 << 40, "gib": 1 << 30, "mib": 1 << 20,
           "kib": 1 << 10, "b": 1, "pb": 10 ** 15, "tb": 10 ** 12, "gb": 10 ** 9}


def parse_size(s: str) -> int:
    """'100GiB' / '1TiB' / '1024' -> bytes (binary suffixes; decimal GB/TB/PB too)."""
    s = s.strip()
    for suf in sorted(_SUFFIX, key=len, reverse=True):
        if s.lower().endswith(suf):
            num = s[: -len(suf)].strip()
            return int(float(num) * _SUFFIX[suf])
    return int(float(s))


def human_bytes(n: float) -> str:
    """bytes -> a compact binary-unit string ('100 GiB', '10 PiB')."""
    n = float(n)
    for name, size in _UNITS:
        if n >= size or name == "B":
            v = n / size
            return (f"{v:.0f} {name}" if abs(v - round(v)) < 1e-9 else f"{v:.3g} {name}")
    return f"{n:.0f} B"


def plot_bytes(n_plot: int) -> int:
    """On-disk labels for one identity's plot = 32 * N_plot (phase1/pospace_drg.py::plot_v3)."""
    return LABEL_BYTES * n_plot


def identities_for(budget: int, n_plot: int) -> int:
    """How many plotted identities a storage budget buys = floor(budget / plot_bytes)."""
    return budget // plot_bytes(n_plot)


def plot_native_seconds(n_plot: int, delta: int = DEFAULT_DELTA) -> float:
    """Native single-core plot TIME for one identity, scaled linearly from FIX_A's 100 GiB floor."""
    base = PLOT_NATIVE_S_PER_100GIB.get(delta, PLOT_NATIVE_S_PER_100GIB[DEFAULT_DELTA])
    return base * (plot_bytes(n_plot) / (100.0 * GIB))


def control_fractions(m: int, n_honest: int, s: int = DEFAULT_S) -> tuple[float, float, float]:
    """(primary-arc, forge/>=1-of-s, majority) chunk-control fractions for m Sybils added to a ring
    of n_honest honest nodes. f = m/(m+n_honest); bounds via b1_placement (consistent with B1/B2)."""
    total = m + n_honest
    if total <= 0:
        return 0.0, 0.0, 0.0
    f = m / total
    primary = m / total
    forge = b1.effective_bound(f, s)       # 1-(1-f)^s
    majority = b1.analytic_bound(f, s)     # 3 f^2 - 2 f^3  (s=3)
    return primary, forge, majority


# =============================================================================================
# Block 1 -- SYBIL YIELD: identities a storage budget buys, at the thesis plot (+ a test-plot row).
# =============================================================================================
def block1_sybil_yield(budgets: list[int], n_plot: int, delta: int) -> list[dict]:
    rows: list[dict] = []
    pb = plot_bytes(n_plot)
    pnat = plot_native_seconds(n_plot, delta)
    for b in budgets:
        m = identities_for(b, n_plot)
        rows.append({
            "metric": "sybil_yield", "source": "analytic", "scheme": "pospace_v3",
            "plot_n": n_plot, "plot_bytes": pb, "plot_h": human_bytes(pb),
            "storage_budget_bytes": b, "storage_budget_h": human_bytes(b), "N_honest": "",
            "identities": m, "f": "", "control_primary": "", "control_forge_1ofs": "",
            "control_majority": "", "plot_seconds_native": pnat,
            "note": f"identities = budget / ({human_bytes(pb)}/plot); delta={delta}",
        })
    # one TEST-plot row: at PLOT_N=1024 (32 KiB) a trivial budget mints astronomically many ids ->
    # the emulation scale is deliberately NOT the security scale (flag, don't hide).
    tb = plot_bytes(TEST_PLOT_N)
    rows.append({
        "metric": "sybil_yield", "source": "analytic", "scheme": "pospace_v3_testplot",
        "plot_n": TEST_PLOT_N, "plot_bytes": tb, "plot_h": human_bytes(tb),
        "storage_budget_bytes": GIB, "storage_budget_h": human_bytes(GIB), "N_honest": "",
        "identities": identities_for(GIB, TEST_PLOT_N), "f": "", "control_primary": "",
        "control_forge_1ofs": "", "control_majority": "",
        "plot_seconds_native": plot_native_seconds(TEST_PLOT_N, delta),
        "note": "TEST plot 2^10 (32 KiB): trivially Sybil-able -- emulation scale, not security scale",
    })
    return rows


# =============================================================================================
# Block 2 -- CHUNK CONTROL: f and control fractions vs budget, analytic + a MEASURED N=32 anchor.
# =============================================================================================
def block2_chunk_control(budgets: list[int], n_plot: int, honest_sizes: list[int],
                         s: int, seed: int) -> list[dict]:
    rows: list[dict] = []
    # analytic: m identities from the thesis plot, added to each parametric honest ring.
    for b in budgets:
        m = identities_for(b, n_plot)
        for nh in honest_sizes:
            total = m + nh
            f = m / total if total else 0.0
            pr, fo, ma = control_fractions(m, nh, s)
            rows.append({
                "metric": "chunk_control", "source": "analytic", "scheme": "pospace_v3",
                "plot_n": n_plot, "plot_bytes": plot_bytes(n_plot), "plot_h": human_bytes(plot_bytes(n_plot)),
                "storage_budget_bytes": b, "storage_budget_h": human_bytes(b), "N_honest": nh,
                "identities": m, "f": f, "control_primary": pr, "control_forge_1ofs": fo,
                "control_majority": ma, "plot_seconds_native": "",
                "note": f"m Sybils added to {nh:,} honest; f=m/(m+N); i.i.d. analytic bounds",
            })
    # MEASURED anchor: m Sybils ADDED to the real 32-node emulation ring (indices 32..32+m-1 are the
    # Sybils, _pk_for placement = RANDOM positions; node 0 stays honest). structural_capture_fraction
    # over the actual converged ring + 1000 served chunks -> a real number, not the i.i.d. limit.
    domains = b1.load_served_domains()
    thresh_maj = b1.capture_threshold(s)                 # majority (2 at s=3)
    for m in ANCHOR_MS:
        ring_n = EMULATION_N + m
        mal = list(range(EMULATION_N, ring_n))           # the added Sybils
        total = EMULATION_N + m
        f = m / total if total else 0.0
        primary = m / total
        forge = b1.structural_capture_fraction(mal, ring_n, s, domains, thresh=1)
        majority = b1.structural_capture_fraction(mal, ring_n, s, domains, thresh=thresh_maj)
        rows.append({
            "metric": "chunk_control", "source": "real_ring", "scheme": "pospace_v3",
            "plot_n": n_plot, "plot_bytes": plot_bytes(n_plot), "plot_h": human_bytes(plot_bytes(n_plot)),
            "storage_budget_bytes": m * plot_bytes(n_plot),
            "storage_budget_h": human_bytes(m * plot_bytes(n_plot)), "N_honest": EMULATION_N,
            "identities": m, "f": f, "control_primary": primary, "control_forge_1ofs": forge,
            "control_majority": majority, "plot_seconds_native": "",
            "note": f"MEASURED: {m} Sybils added to 32-node ring (random placement), "
                    f"{len(domains)} served chunks",
        })
    return rows


# =============================================================================================
# Block 3 -- POSPACE vs FREE: the headline "PoSpace raises the cost".
# =============================================================================================
def block3_pospace_vs_free(budgets: list[int], n_plot: int, n_honest: int, s: int) -> list[dict]:
    rows: list[dict] = []
    pb = plot_bytes(n_plot)
    for b in budgets:
        # WITHOUT admission: an identity is just a keypair (~33 B) -> ~unbounded ids -> f->1.
        m_free = b // PK_BYTES
        pr_f, fo_f, ma_f = control_fractions(m_free, n_honest, s)
        rows.append({
            "metric": "pospace_vs_free", "source": "analytic", "scheme": "none",
            "plot_n": "", "plot_bytes": PK_BYTES, "plot_h": f"{PK_BYTES} B/id",
            "storage_budget_bytes": b, "storage_budget_h": human_bytes(b), "N_honest": n_honest,
            "identities": m_free, "f": m_free / (m_free + n_honest), "control_primary": pr_f,
            "control_forge_1ofs": fo_f, "control_majority": ma_f, "plot_seconds_native": "",
            "note": f"NO admission: identity=keypair ({PK_BYTES} B) -> f->1, full control",
        })
        # WITH v3-DRG PoSpace: identity = one 100 GiB plot.
        m_ps = identities_for(b, n_plot)
        pr_p, fo_p, ma_p = control_fractions(m_ps, n_honest, s)
        rows.append({
            "metric": "pospace_vs_free", "source": "analytic", "scheme": "pospace_v3",
            "plot_n": n_plot, "plot_bytes": pb, "plot_h": human_bytes(pb),
            "storage_budget_bytes": b, "storage_budget_h": human_bytes(b), "N_honest": n_honest,
            "identities": m_ps, "f": m_ps / (m_ps + n_honest), "control_primary": pr_p,
            "control_forge_1ofs": fo_p, "control_majority": ma_p, "plot_seconds_native": "",
            "note": f"PoSpace v3: identity={human_bytes(pb)} plot; cost x{pb // PK_BYTES:,} vs free",
        })
    return rows


# =============================================================================================
# Block 4 -- in-process admission demo: k distinct Sybils each need their OWN plot (no amortisation).
# =============================================================================================
def block4_admission_demo(seed: int) -> list[dict]:
    """Admit k distinct Sybils on a real in-process PoSpace ring (A7 pattern) and show each built its
    OWN plot (k distinct commitment roots) and the pk<->id binding blocks plot reuse. Lazily imports
    the node stack (dnspython): returns a skipped row if it is unavailable, so the cost analysis runs
    anywhere."""
    def _skip(reason: str) -> list[dict]:
        return [{
            "metric": "admission_demo", "source": "admission_inproc", "scheme": "pospace_v3",
            "plot_n": DEMO_PLOT_N, "plot_bytes": plot_bytes(DEMO_PLOT_N),
            "plot_h": human_bytes(plot_bytes(DEMO_PLOT_N)), "storage_budget_bytes": "",
            "storage_budget_h": "", "N_honest": DEMO_HONEST_N, "identities": "", "f": "",
            "control_primary": "", "control_forge_1ofs": "", "control_majority": "",
            "plot_seconds_native": "", "note": f"in-process demo skipped ({reason})",
        }]

    try:
        import asyncio
        from node.net import Network
        from node.pospace_admission import PoSpaceNode
        from node.ids import node_id_from_pk as _nid
        from node.run_node import _pk_for
    except Exception as e:                                           # dnspython / env missing
        return _skip(f"import failed: {type(e).__name__}; run under the 3.11 env with dnspython")

    async def _converge(nodes, rounds: int) -> None:
        for _ in range(rounds):
            for nd in nodes:
                if nd.alive:
                    await nd.stabilize()
            for nd in nodes:
                if nd.alive:
                    await nd.fix_fingers()
                    await nd.check_predecessor()
            await asyncio.sleep(0)

    async def _run() -> dict:
        net = Network()
        nodes = [PoSpaceNode(_pk_for(j), net, plot_n=DEMO_PLOT_N, seed=seed)
                 for j in range(DEMO_HONEST_N)]
        await nodes[0].create()
        for nd in nodes[1:]:
            await nd.join(nodes[0].node_id)
            await _converge(nodes, rounds=6)

        # Admit k distinct Sybils, each with its OWN pk -> its OWN plot.
        sybils, roots, ids, admitted = [], [], [], 0
        for k in range(DEMO_SYBILS):
            pk = b"b5-sybil-" + k.to_bytes(4, "big") + b"\x00" * 20
            syb = PoSpaceNode(pk, net, plot_n=DEMO_PLOT_N, seed=seed)
            ok = True
            try:
                await syb.join(nodes[0].node_id)        # real gated admission (build plot + challenge)
            except Exception:
                ok = False
            await _converge(nodes + sybils + [syb], rounds=4)
            if ok:
                admitted += 1
            sybils.append(syb)
            roots.append(syb.plot_root)
            ids.append(syb.node_id)

        # No-amortisation / binding checks: distinct pks -> distinct roots -> distinct ids; and the
        # id of each Sybil is exactly node_id_from_pk(pk) (so one plot's pk cannot masquerade as another
        # id -- the challenger rejects node_id_from_pk(pk) != peer_id).
        distinct_roots = len({r for r in roots if r is not None}) == DEMO_SYBILS
        distinct_ids = len(set(ids)) == DEMO_SYBILS
        binding_ok = all(syb.node_id == _nid(syb.pk) for syb in sybils)

        for nd in nodes + sybils:
            nd.stop()
        return {"admitted": admitted, "distinct_roots": distinct_roots,
                "distinct_ids": distinct_ids, "binding_ok": binding_ok}

    res = asyncio.run(_run())
    ok = (res["admitted"] == DEMO_SYBILS and res["distinct_roots"]
          and res["distinct_ids"] and res["binding_ok"])
    return [{
        "metric": "admission_demo", "source": "admission_inproc", "scheme": "pospace_v3",
        "plot_n": DEMO_PLOT_N, "plot_bytes": plot_bytes(DEMO_PLOT_N),
        "plot_h": human_bytes(plot_bytes(DEMO_PLOT_N)), "storage_budget_bytes": "",
        "storage_budget_h": "", "N_honest": DEMO_HONEST_N, "identities": res["admitted"],
        "f": "", "control_primary": "", "control_forge_1ofs": "", "control_majority": "",
        "plot_seconds_native": "",
        "note": f"admitted {res['admitted']}/{DEMO_SYBILS} Sybils; distinct_roots="
                f"{res['distinct_roots']} binding_ok={res['binding_ok']} -> one plot per identity "
                f"(no amortisation); overall={'ok' if ok else 'OFF'}",
    }]


# =============================================================================================
# Control -- honest zero budget -> 0 identities -> structural capture 0 (adversary-caused).
# =============================================================================================
def control_row(n: int, s: int) -> list[dict]:
    frac = b1.structural_capture_fraction([], n, s)          # no Sybils
    return [{
        "metric": "control", "source": "real_ring", "scheme": "pospace_v3", "plot_n": "",
        "plot_bytes": "", "plot_h": "", "storage_budget_bytes": 0, "storage_budget_h": "0 B",
        "N_honest": n, "identities": 0, "f": 0.0, "control_primary": 0.0,
        "control_forge_1ofs": frac, "control_majority": frac, "plot_seconds_native": "",
        "note": "zero budget -> 0 Sybils: structural capture over all served chunks",
    }]


# =============================================================================================
# CSV.
# =============================================================================================
FIELDS = ["metric", "source", "scheme", "plot_n", "plot_bytes", "plot_h",
          "storage_budget_bytes", "storage_budget_h", "N_honest", "identities", "f",
          "control_primary", "control_forge_1ofs", "control_majority", "plot_seconds_native",
          "note"]

_METRIC_ORDER = {"sybil_yield": 0, "chunk_control": 1, "pospace_vs_free": 2,
                 "admission_demo": 3, "control": 4}


def _fmt(v) -> str:
    if isinstance(v, float):
        if math.isnan(v):
            return ""
        if abs(v) >= 1e6 or (v != 0 and abs(v) < 1e-4):
            return f"{v:.6g}"
        return f"{v:.4f}"
    return str(v)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def write_csv(rows: list[dict]) -> None:
    def key(r):
        b = r.get("storage_budget_bytes", 0)
        b = b if isinstance(b, int) else 0
        nh = r.get("N_honest", 0)
        nh = nh if isinstance(nh, int) else 0
        return (_METRIC_ORDER.get(r["metric"], 9), b, nh, str(r.get("scheme", "")),
                str(r.get("source", "")))
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=key):
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# =============================================================================================
# Figure: (1) identities vs storage budget (log-log): PoSpace v3 vs free (no admission);
# (2) chunk control (forge >=1-of-s) vs budget for N_honest in {32, 1e3, 1e6}, with the MEASURED
# N=32 structural anchor overlaid. Style mirrors A7/B2.
# =============================================================================================
def make_plot(rows: list[dict]) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:                                           # no matplotlib in this env
        print(f"(skipping figure: matplotlib unavailable -- {type(e).__name__}; "
              f"regenerate with --no-plot off under the plotting env)")
        return

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    PSC, FREEC = "#2a78d6", "#8a1c5a"
    NHC = {32: "#1baf7a", 1_000: "#2a78d6", 1_000_000: "#0b3a66"}
    ANCHORC = "#e08a1e"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    # --- panel 1: identities vs storage budget (PoSpace vs free) ---
    ax = axes[0]
    pv = [r for r in rows if r["metric"] == "pospace_vs_free"]
    budgets = sorted({r["storage_budget_bytes"] for r in pv})
    free = {r["storage_budget_bytes"]: r["identities"] for r in pv if r["scheme"] == "none"}
    ps = {r["storage_budget_bytes"]: r["identities"] for r in pv if r["scheme"] == "pospace_v3"}
    ax.plot(budgets, [max(1e-1, free.get(b, 0)) for b in budgets], marker="o", ms=5, lw=1.8,
            color=FREEC, label=f"no admission ({PK_BYTES} B/id)")
    ax.plot(budgets, [max(1e-1, ps.get(b, 0)) for b in budgets], marker="s", ms=5, lw=1.8,
            color=PSC, label=f"PoSpace v3 ({human_bytes(plot_bytes(REAL_PLOT_N))}/id)")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("storage budget (bytes)"); ax.set_ylabel("Sybil identities minted")
    ax.set_title("Sybil yield: PoSpace pins each identity to a plot")
    ax.legend(frameon=False, fontsize=8, loc="upper left")

    # --- panel 2: chunk control (forge >=1-of-s) vs budget, by honest ring size ---
    ax = axes[1]
    cc = [r for r in rows if r["metric"] == "chunk_control"]
    an = [r for r in cc if r["source"] == "analytic" and r["scheme"] == "pospace_v3"]
    an_budgets = sorted({r["storage_budget_bytes"] for r in an})
    for nh in sorted(NHC):
        ys = {r["storage_budget_bytes"]: r["control_forge_1ofs"] for r in an if r["N_honest"] == nh}
        ser = [ys.get(b, float("nan")) for b in an_budgets]
        if any(not math.isnan(v) for v in ser):
            ax.plot(an_budgets, ser, marker="o", ms=4, lw=1.7, color=NHC[nh],
                    label=f"N_honest = {nh:,}")
    # measured N=32 structural anchor (budget = m * 100 GiB)
    anchor = [r for r in cc if r["source"] == "real_ring"]
    axb = [r["storage_budget_bytes"] for r in anchor if r["storage_budget_bytes"]]
    axy = [r["control_forge_1ofs"] for r in anchor if r["storage_budget_bytes"]]
    if axb:
        ax.plot(axb, axy, marker="D", ms=6, lw=0, color=ANCHORC,
                label="measured N=32 (structural)")
    ax.set_xscale("log")
    ax.set_xlabel("storage budget (bytes)"); ax.set_ylabel("chunk space controlled (forge, >=1-of-s)")
    ax.set_ylim(-0.03, 1.03)
    ax.set_title("Chunk control vs budget: bigger ring needs more budget")
    ax.legend(frameon=False, fontsize=8, loc="upper left")

    fig.suptitle("B5 — Sybil vs PoSpace admission: one identity = one ~100 GiB plot; "
                 "admission raises the Sybil cost ~3.25e9x", y=1.03, fontsize=11)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# =============================================================================================
# Self-test -- deterministic, no Docker (the plan's verification step).
# =============================================================================================
def _self_test() -> int:
    ok = True
    s = DEFAULT_S
    pb = plot_bytes(REAL_PLOT_N)
    print(f"[self-test] s={s} thesis plot={human_bytes(pb)} ({pb:,} B) PK={PK_BYTES} B")

    # (a) identities = budget // (32*N_plot) on known values.
    a_ok = (identities_for(pb, REAL_PLOT_N) == 1
            and identities_for(10 * pb, REAL_PLOT_N) == 10
            and plot_bytes(REAL_PLOT_N) == 100 * GIB)
    ok &= a_ok
    print(f"  (a) 100 GiB plot; 1 budget->1 id, 10 budget->10 ids  [{'ok' if a_ok else 'OFF'}]")

    # (b) at 100 GiB plot, exactly budget/100GiB identities; test plot mints vastly more.
    big = 1 << 50                                                   # 1 PiB
    b_ok = (identities_for(big, REAL_PLOT_N) == big // pb
            and identities_for(GIB, TEST_PLOT_N) > identities_for(GIB, REAL_PLOT_N))
    ok &= b_ok
    print(f"  (b) 1 PiB -> {identities_for(big, REAL_PLOT_N):,} ids; test plot >> thesis  "
          f"[{'ok' if b_ok else 'OFF'}]")

    # (c) control fractions monotone in m and ordered majority <= forge <= 1.
    c_ok = True
    prev_forge = -1.0
    for m in [0, 1, 5, 50, 5000]:
        pr, fo, ma = control_fractions(m, 1000, s)
        if not (0.0 <= ma <= fo <= 1.0 + 1e-12 and fo >= prev_forge - 1e-12):
            c_ok = False
        prev_forge = fo
    ok &= c_ok
    print(f"  (c) control monotone & majority<=forge<=1  [{'ok' if c_ok else 'OFF'}]")

    # (d) measured N=32 structural anchor matches the i.i.d. bounds within B1's tolerance.
    domains = b1.load_served_domains()
    d_ok = True
    for m in [3, 10, 16]:
        ring_n = EMULATION_N + m
        mal = list(range(EMULATION_N, ring_n))
        f = m / ring_n
        meas_forge = b1.structural_capture_fraction(mal, ring_n, s, domains, thresh=1)
        bound_forge = b1.effective_bound(f, s)
        tol = 0.05 + 0.15 * bound_forge
        flag = abs(meas_forge - bound_forge) <= tol
        d_ok &= flag
        print(f"      m={m:>2} f={f:.3f} measured_forge={meas_forge:.4f} "
              f"bound={bound_forge:.4f}  [{'ok' if flag else 'OFF'}]")
    ok &= d_ok
    print(f"  (d) measured anchor ~ analytic bound  [{'ok' if d_ok else 'OFF'}]")

    # (e) pospace_vs_free: free control -> ~1.0, pospace control < free at a realistic budget.
    pvf = block3_pospace_vs_free([1 << 50], REAL_PLOT_N, FREE_REF_HONEST, s)  # 1 PiB
    free_r = next(r for r in pvf if r["scheme"] == "none")
    ps_r = next(r for r in pvf if r["scheme"] == "pospace_v3")
    e_ok = free_r["control_forge_1ofs"] > 0.999 and ps_r["control_forge_1ofs"] < free_r["control_forge_1ofs"]
    ok &= e_ok
    print(f"  (e) 1 PiB: free control={free_r['control_forge_1ofs']:.4f} "
          f"pospace control={ps_r['control_forge_1ofs']:.4f}  [{'ok' if e_ok else 'OFF'}]")

    # (f) honest control: zero budget -> 0 structural capture.
    f_frac = control_row(EMULATION_N, s)[0]["control_forge_1ofs"]
    f_ok = f_frac == 0.0
    ok &= f_ok
    print(f"  (f) zero-budget control capture={f_frac:.4f}  [{'ok' if f_ok else 'OFF'}]")

    # (g) in-process admission demo (skips cleanly if dnspython absent).
    demo = block4_admission_demo(SEED)[0]
    if "skipped" in demo["note"]:
        print(f"  (g) admission demo SKIPPED ({demo['note'].split('(', 1)[-1].rstrip(')')})")
    else:
        g_ok = "overall=ok" in demo["note"]
        ok &= g_ok
        print(f"  (g) {demo['note']}  [{'ok' if g_ok else 'OFF'}]")

    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# =============================================================================================
def main() -> int:
    ap = argparse.ArgumentParser(description="B5 Sybil vs PoSpace admission (issue #46).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--no-demo", action="store_true", help="skip the in-process admission demo")
    ap.add_argument("--self-test", action="store_true", help="deterministic checks, no Docker")
    ap.add_argument("--budgets", default=",".join(DEFAULT_BUDGETS),
                    help="comma list of storage budgets (e.g. 100GiB,1TiB,1PiB)")
    ap.add_argument("--n-plot", type=int, default=REAL_PLOT_N,
                    help="plot size (leaf count) priced per identity (default = thesis REAL_PLOT_N)")
    ap.add_argument("--honest-sizes", default=",".join(str(x) for x in DEFAULT_HONEST),
                    help="comma list of honest ring sizes for the analytic control curves")
    ap.add_argument("--delta", type=int, default=DEFAULT_DELTA, choices=[2, 4, 8],
                    help="DRG in-degree for the plot-TIME column (storage is delta-independent)")
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()

    if args.self_test:
        return _self_test()

    budgets = [parse_size(x) for x in args.budgets.split(",") if x]
    honest_sizes = [int(x) for x in args.honest_sizes.split(",") if x]
    n_plot = args.n_plot
    pb = plot_bytes(n_plot)
    print(f"B5 Sybil vs PoSpace admission — seed={args.seed}, plot_n={n_plot:,} "
          f"({human_bytes(pb)}/identity), s={DEFAULT_S}, delta={args.delta}")

    rows: list[dict] = []

    print("\n== Block 1: Sybil yield (identities per storage budget) ==")
    y_rows = block1_sybil_yield(budgets, n_plot, args.delta)
    rows += y_rows
    for r in y_rows:
        if r["scheme"] == "pospace_v3":
            print(f"  budget={r['storage_budget_h']:>8}  identities={r['identities']:>18,}  "
                  f"plot_time/id~{r['plot_seconds_native']/60:.1f} min (native, delta={args.delta})")

    print("\n== Block 2: chunk control vs budget (analytic + measured N=32 anchor) ==")
    c_rows = block2_chunk_control(budgets, n_plot, honest_sizes, DEFAULT_S, args.seed)
    rows += c_rows
    for nh in honest_sizes:
        sub = [r for r in c_rows if r["source"] == "analytic" and r["N_honest"] == nh]
        if sub:
            lo, hi = sub[0], sub[-1]
            print(f"  N_honest={nh:>9,}: budget {lo['storage_budget_h']}->{hi['storage_budget_h']}  "
                  f"forge-control {lo['control_forge_1ofs']:.4f}->{hi['control_forge_1ofs']:.4f}")
    anchor = [r for r in c_rows if r["source"] == "real_ring"]
    print(f"  MEASURED N=32 anchor: m={anchor[1]['identities']} forge={anchor[1]['control_forge_1ofs']:.4f} "
          f"... m={anchor[-1]['identities']} forge={anchor[-1]['control_forge_1ofs']:.4f}")

    print("\n== Block 3: PoSpace vs free (the cost PoSpace imposes) ==")
    v_rows = block3_pospace_vs_free(budgets, n_plot, FREE_REF_HONEST, DEFAULT_S)
    rows += v_rows
    print(f"  (N_honest={FREE_REF_HONEST:,} reference)")
    for b in budgets:
        fr = next(r for r in v_rows if r["storage_budget_bytes"] == b and r["scheme"] == "none")
        ps = next(r for r in v_rows if r["storage_budget_bytes"] == b and r["scheme"] == "pospace_v3")
        print(f"  budget={fr['storage_budget_h']:>8}  free: ids={fr['identities']:,.0f} ctrl="
              f"{fr['control_forge_1ofs']:.3f}  |  pospace: ids={ps['identities']:,} ctrl="
              f"{ps['control_forge_1ofs']:.4f}")

    if not args.no_demo:
        print("\n== Block 4: in-process admission demo (k Sybils, one plot each) ==")
        demo_rows = block4_admission_demo(args.seed)
        rows += demo_rows
        print(f"  {demo_rows[0]['note']}")

    rows += control_row(EMULATION_N, DEFAULT_S)
    print(f"\n== Control: zero-budget structural capture = {rows[-1]['control_forge_1ofs']:.4f} ==")

    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
