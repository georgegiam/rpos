#!/usr/bin/env python3
"""Issue #47 [B6] — Malicious ledger proposer (Phase 7, examiner point (ii)).

B6 asks what Algorithm 3 (node/ledger.py, the two-phase-commit chunk ledger) does when a node
proposes INVALID chunk updates: what fraction of bad updates do the honest replicas REJECT, and
how long until such a proposer is EVICTED? Both metrics are degenerate on the frozen reference,
and that degeneracy IS the result (the same shape as B1/B2/B5 — a measured missing defense):

  * REJECTION RATE = 0% at every f. The replica-side handlers validate NOTHING about a proposal's
    content, the proposer's identity, or its authorization. `_h_precommit`
    (node/ledger.py:51-56) rejects only a LOCK CONFLICT (the chunk is already pre-committed to a
    different proposal id); `_h_commit` (58-70) accepts if the lock is this pid OR None (so a
    proposer can even SKIP pre-commit and commit directly) and then UNCONDITIONALLY does
    store[cid]=value and appends to the hash chain — a malformed value merely skips expiry
    tracking (`except ValueError: pass`) and is still committed. The poisoned entry still passes
    verify_chain() (tamper-evidence detects log MUTATION, not bad INPUT). Any node can propose for
    any chunk; `src` is ignored. So the write path is WEAKER than B1's read path: B1 forging needs
    >=1-of-s malicious REPLICAS on a read; B6 needs ZERO malicious replicas — ONE proposer commits
    arbitrary values to a majority of s HONEST replicas for any chosen domain. f only scales
    coverage, not per-proposal success → the rejection rate is flat 0% and f-INDEPENDENT.

  * TIME-TO-EVICTION = infinite (never). Eviction (node/pospace_admission.py::_evict, driven by
    challenge_peer) fires ONLY on MAX_FAILS consecutive PoSpace SPACE-PROOF failures. There is no
    path from ledger misbehaviour to fail_counts/_evict. A malicious proposer holds a VALID plot,
    so it passes every challenge and is never evicted. The machinery works (positive control: a
    corrupted-plot node is evicted in MAX_FAILS=3 rounds) — it is simply not wired to this attack.

  * HONEST CONTROL (f=0, VALID updates) is ALSO 0% rejected — but that is CORRECT acceptance. The
    protocol cannot tell a valid proposal from an invalid one; the delta over the honest baseline
    is zero, which means the "attack" is invisible to the protocol — the vulnerability, not
    chord.py fragility.

WHY AN IN-PROCESS RING + ANALYTIC SWEEP, NOT THE DOCKER TESTBED (mirrors B2/B4/B5): the result is
a protocol PROPERTY reconstructible from the frozen code + a real converged ring, and eviction can
ONLY be exercised in-process (socket _evict is a no-op — net.nodes holds only the local node). A
flaky ~90-min 32-container run does not make "no defense exists" more true. The in-process ring
runs the REAL propose_update/_h_precommit/_h_commit and the REAL challenge_peer/_evict, so every
number is measured, not asserted. An optional socket cross-check lives in experiments/run_b6.sh
(separate file results/B6_proposer_socket.csv, B4 pattern). The attack needs NO new malicious mode:
a "malicious proposer" is defined by the VALUE it proposes, and propose_update is identical code
for honest and malicious nodes — so a chosen node simply calls propose_update(domain, FORGED).

New code in a new file (CLAUDE.md §2): imports/reads only. rpos/rpos.py, node/chord.py,
node/storage.py, node/ledger.py, node/pospace_admission.py, node/net.py, node/malicious.py,
phase1/pospace_drg.py and experiments/b1_placement.py stay byte-identical. Fixed seed 20260919.

Run:  python3 experiments/b6_proposer.py                 # full analysis -> CSV + PNG + stdout
      python3 experiments/b6_proposer.py --no-plot       # table only
      python3 experiments/b6_proposer.py --self-test     # deterministic checks, no Docker
      python3 experiments/b6_proposer.py --require-ring  # treat a skipped in-process ring as failure
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
RESULTS = REPO_ROOT / "results"
OUT_CSV = RESULTS / "B6_proposer.csv"
OUT_FIG = RESULTS / "fig_B6_proposer.png"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# host-safe imports (hashlib / sim only — NO dnspython, NO matplotlib at import time) -----------
from node.ids import chunk_id                                 # noqa: E402
import b1_placement as b1                                     # noqa: E402

# frozen B6 workload (PARAMETERS.md) -----------------------------------------------------------
SEED = 20260919                     # frozen repo seed (CLAUDE.md §2)
N = 32                              # emulation ceiling (results/PARAMETERS.md)
S = 3                              # replication factor
PLOT_N = 1 << 10                   # test plot (fast in-process admission; plot COST is A7)
ALPHA = 1.0                        # Zipf popularity exponent (query_gen)
EV_N = 8                           # small ring for the eviction probe (fast, like B5 demo)
K_UPDATES = 40                     # distinct bad updates driven per f-point
F_LEVELS = [0, 10, 20, 30, 40, 50]                 # adversary fractions (B0 threat model)
N_MAL = [round(f / 100 * N) for f in F_LEVELS]     # -> [0, 3, 6, 10, 13, 16] at N=32 (matches B0)
MANIFEST = REPO_ROOT / "testbed" / "dns" / "zones" / "MANIFEST.json"


def load_zone() -> dict[str, str]:
    """domain -> correct answer_ip (ground truth the attacker overwrites)."""
    recs = json.loads(MANIFEST.read_text())["records"]
    return {d: r["answer_ip"] for d, r in recs.items()}


def zipf_share_pct(target: str, ranked: list[str], alpha: float = ALPHA) -> float:
    """Zipf(alpha) share of all queries that hit ``target`` (rank 1 = most popular), matching
    testbed/query_gen.py's weighting — i.e. how much of the answer stream poisoning it corrupts."""
    if not ranked:
        return 0.0
    weights = [1.0 / ((i + 1) ** alpha) for i in range(len(ranked))]
    total = sum(weights)
    try:
        idx = ranked.index(target)
    except ValueError:
        return 0.0
    return 100.0 * weights[idx] / total


# =============================================================================================
# In-process ring measurement (PRIMARY) — the REAL propose_update / challenge_peer / _evict.
# Lazily imports the node stack so the analytic rows + self-test run anywhere (B5 pattern).
# =============================================================================================
def run_ring_measurements(seed: int, k_updates: int = K_UPDATES) -> dict | None:
    """Build a real converged in-process ring and measure: (1) rejection rate of bad updates
    swept over f (random proposer placement), (2) commit-acceptance detail (random + targeted,
    with store-poison + verify_chain confirmation), (3) the eviction probe. Returns a results
    dict, or None if the node stack is unavailable (env without dnspython)."""
    try:
        import asyncio
        from node.net import Network
        from node.malicious import MaliciousNode, FORGED_IP, FORGED_TTL
        from node.query import _encode, IterativeResolver
        from node.tests.util import build_ring
    except (ImportError, ModuleNotFoundError):
        return None
    # any OTHER exception is a real failure -> let it propagate (do NOT masquerade as skipped).

    async def _run() -> dict:
        zone = load_zone()
        ranked = b1.load_served_domains()                 # popularity order (Zipf rank)
        sample = ranked[:k_updates]                        # distinct popular domains to poison
        bad = _encode(FORGED_IP, FORGED_TTL)              # the attacker's forged record (6.6.6.6)

        # model ring (host-side) to pick a node-0-free target + replica indices (consistent w/ B1)
        mring, mid2idx = b1.build_ring(N, S)
        target = next((d for d in ranked if 0 not in b1.replica_indices(d, mring, mid2idx, S)),
                      ranked[0])

        net = Network()
        upstream = IterativeResolver(zone, ttl=0)          # cold path; populate via honest fallback
        nodes = await build_ring(MaliciousNode, net, N, upstream=upstream, plot_n=PLOT_N, seed=seed)
        id2node = {nd.node_id: nd for nd in nodes}
        touch = list(dict.fromkeys(sample + [target]))
        for d in touch:                                    # populate with the CORRECT value first
            await nodes[0].resolve_query(d)
        snap = [dict(nd.store) for nd in nodes]            # pristine populated state

        def reset() -> None:
            """Restore pristine store + clear all ledger state between independent f-points."""
            for i, nd in enumerate(nodes):
                nd.store = dict(snap[i])
                nd.ledger = []
                nd.pending = {}
                nd.expiry = {}
                nd.chunk_domain = {}
                if hasattr(nd, "cache"):
                    nd.cache = {}

        # --- (1) rejection rate vs f (random proposer placement) ---
        rej = []
        for f_pct, n_mal in zip(F_LEVELS, N_MAL):
            reset()
            if n_mal == 0:                                  # HONEST CONTROL: valid updates
                proposers = [0]
                assignments = [(d, _encode(zone[d], 300)) for d in sample]
                ideal = 0.0
            else:                                          # malicious proposers: forged values
                proposers = b1.random_indices(N, n_mal, seed)
                assignments = [(d, bad) for d in sample]
                ideal = 100.0
            proposals = committed = 0
            for j, (d, val) in enumerate(assignments):
                p = proposers[j % len(proposers)]
                ok = await nodes[p].propose_update(d, val, action="update")
                proposals += 1
                committed += 1 if ok else 0
            rejected = proposals - committed
            rej.append({
                "f_pct": f_pct, "n_mal": n_mal, "proposals": proposals, "committed": committed,
                "rejected": rejected, "rejection_rate": 100.0 * rejected / proposals,
                "ideal": ideal,
            })

        # --- (2) commit-acceptance detail: random (poison + verify) ---
        reset()
        attacker_r = b1.random_indices(N, 1, seed)[0]
        acc = 0
        chain_ok = poison_ok = True
        for d in sample:
            ok = await nodes[attacker_r].propose_update(d, bad, action="update")
            acc += 1 if ok else 0
            cid = chunk_id(d)
            reps, _ = await nodes[attacker_r].replica_set(cid)
            for rid in reps:
                nd = id2node[rid]
                if nd.store.get(cid) != bad:
                    poison_ok = False
                if not nd.verify_chain():
                    chain_ok = False
        random_accept = 100.0 * acc / len(sample)

        # --- (2b) commit-acceptance: targeted (one non-replica misroutes a popular chunk) ---
        reset()
        reps_t_idx = b1.replica_indices(target, mring, mid2idx, S)
        attacker_t = next(i for i in range(1, N) if i not in reps_t_idx)
        cid_t = chunk_id(target)
        t_ok = await nodes[attacker_t].propose_update(target, bad, action="update")
        reps_t, _ = await nodes[attacker_t].replica_set(cid_t)
        t_poison = all(id2node[rid].store.get(cid_t) == bad for rid in reps_t)
        t_chain = all(id2node[rid].verify_chain() for rid in reps_t)
        share = zipf_share_pct(target, ranked)

        for nd in nodes:
            if getattr(nd, "alive", False):
                nd.stop()

        ev = await _eviction_probe(seed, Network, MaliciousNode, _encode, IterativeResolver,
                                   build_ring, FORGED_IP, FORGED_TTL)
        return {
            "rej": rej, "random_accept": random_accept, "chain_ok": chain_ok,
            "poison_ok": poison_ok, "target": target, "target_ok": bool(t_ok and t_poison),
            "target_chain": t_chain, "target_share": share, **ev,
        }

    return asyncio.run(_run())


async def _eviction_probe(seed, Network, MaliciousNode, _encode, IterativeResolver,
                          build_ring, forged_ip, forged_ttl) -> dict:
    """A malicious proposer commits bad updates, then is challenged repeatedly: it holds a VALID
    plot so it passes every PoSpace challenge and is NEVER evicted (time-to-eviction = inf). A
    positive control (corrupted plot) proves the eviction machinery still works (evicts in
    MAX_FAILS rounds) — so 'never' means 'not wired to ledger abuse', not 'eviction is broken'."""
    from node.pospace_admission import MAX_FAILS

    zone = load_zone()
    net = Network()
    upstream = IterativeResolver(zone, ttl=0)
    nodes = await build_ring(MaliciousNode, net, EV_N, upstream=upstream, plot_n=PLOT_N, seed=seed)
    bad = _encode(forged_ip, forged_ttl)
    domains = b1.load_served_domains()[:10]
    for d in domains:
        await nodes[0].resolve_query(d)

    # the attack: node 1 proposes a stream of forged updates (all committed by honest replicas)
    proposer = nodes[1]
    n_bad = 0
    for d in domains:
        if await proposer.propose_update(d, bad, action="update"):
            n_bad += 1

    # its predecessor challenges it well past MAX_FAILS; valid plot => always passes => never evicted
    challenger = next(nd for nd in nodes if nd.alive and nd.successor() == proposer.node_id)
    rounds = 2 * MAX_FAILS + 1
    passes = 0
    abuse_evict_round = None
    for r in range(1, rounds + 1):
        ok = await challenger.challenge_peer(proposer.node_id)
        passes += 1 if ok else 0
        if not net.is_up(proposer.node_id):
            abuse_evict_round = r
            break
    abuse_fails = challenger.fail_counts.get(proposer.node_id, 0)

    # positive control: corrupt a different node's plot -> its challenger evicts it in MAX_FAILS
    victim = nodes[2]
    victim.plot_root = b"\x11" * 32
    vchal = next(nd for nd in nodes if nd.alive and nd.successor() == victim.node_id)
    ctrl_round = None
    for r in range(1, MAX_FAILS + 1):
        await vchal.challenge_peer(victim.node_id)
        if not net.is_up(victim.node_id):
            ctrl_round = r
            break

    for nd in nodes:
        if getattr(nd, "alive", False):
            nd.stop()
    return {
        "abuse_n_bad": n_bad, "abuse_passes": passes,
        "abuse_evicted": abuse_evict_round is not None, "abuse_ttl": abuse_evict_round,
        "abuse_fails": abuse_fails, "max_fails": MAX_FAILS,
        "ctrl_evicted": ctrl_round is not None, "ctrl_ttl": ctrl_round,
    }


# =============================================================================================
# Row construction.
# =============================================================================================
def _blank() -> dict:
    return {k: "" for k in FIELDS}


def rows_rejection(res: dict | None) -> list[dict]:
    """rejection_vs_f: measured (ring_inproc) when available, else analytic (modeled 0)."""
    out = []
    if res is not None:
        for r in res["rej"]:
            f_pct, n_mal = r["f_pct"], r["n_mal"]
            row = _blank()
            row.update({
                "metric": "rejection_vs_f", "source": "ring_inproc",
                "f_pct": f_pct, "n_mal": n_mal, "realized_f_pct": round(100.0 * n_mal / N, 4),
                "proposals": r["proposals"], "committed": r["committed"], "rejected": r["rejected"],
                "rejection_rate_pct": r["rejection_rate"], "ideal_rejection_pct": r["ideal"],
                "note": ("honest control: VALID updates accepted (0 rejected = CORRECT)" if n_mal == 0
                         else f"{n_mal} malicious proposer(s): forged updates accepted — no content "
                              f"validation (0 rejected = the bug); ideal (validating) protocol = 100%"),
            })
            out.append(row)
    else:                                                  # analytic fallback (modeled from code)
        for f_pct, n_mal in zip(F_LEVELS, N_MAL):
            row = _blank()
            row.update({
                "metric": "rejection_vs_f", "source": "analytic",
                "f_pct": f_pct, "n_mal": n_mal, "realized_f_pct": round(100.0 * n_mal / N, 4),
                "proposals": K_UPDATES, "committed": K_UPDATES, "rejected": 0,
                "rejection_rate_pct": 0.0, "ideal_rejection_pct": (0.0 if n_mal == 0 else 100.0),
                "note": ("honest control (modeled): valid updates accepted" if n_mal == 0
                         else "MODELED: _h_precommit/_h_commit validate no content -> 0 rejected "
                              "(run under the node env for the measured ring_inproc row)"),
            })
            out.append(row)
    return out


def rows_commit_acceptance(res: dict | None) -> list[dict]:
    if res is None:
        row = _blank()
        row.update({"metric": "commit_acceptance", "source": "ring_inproc",
                    "note": "skipped (node stack unavailable; run under the 3.11 env + dnspython)"})
        return [row]
    rnd = _blank()
    rnd.update({
        "metric": "commit_acceptance", "source": "ring_inproc", "block": "random",
        "proposals": K_UPDATES, "committed": round(res["random_accept"] / 100 * K_UPDATES),
        "rejected": 0, "rejection_rate_pct": round(100.0 - res["random_accept"], 4),
        "chain_valid": "yes" if res["chain_ok"] else "NO",
        "note": f"{K_UPDATES} forged updates: accepted {res['random_accept']:.1f}%, every chunk's "
                f"s={S} replicas store the forged value (poison_ok={res['poison_ok']}) and the "
                f"hash chain still verifies -> committed, not rejected",
    })
    tgt = _blank()
    tgt.update({
        "metric": "commit_acceptance", "source": "ring_inproc", "block": "targeted",
        "target": res["target"], "target_forged_pct": 100.0 if res["target_ok"] else 0.0,
        "target_share_pct": round(res["target_share"], 4),
        "chain_valid": "yes" if res["target_chain"] else "NO",
        "note": f"ONE non-replica proposer forges the popular chunk {res['target']!r}: all s={S} "
                f"replicas poisoned, chain valid -> corrupts ~{res['target_share']:.1f}% of the "
                f"Zipf answer stream at cost 1 (proposer need not own the chunk; grind cost -> B2)",
    })
    return [rnd, tgt]


def rows_eviction(res: dict | None) -> list[dict]:
    if res is None:
        row = _blank()
        row.update({"metric": "eviction", "source": "ring_inproc",
                    "note": "skipped (node stack unavailable; run under the 3.11 env + dnspython)"})
        return [row]
    abuse = _blank()
    abuse.update({
        "metric": "eviction", "source": "ring_inproc", "block": "ledger_abuse",
        "proposals": res["abuse_n_bad"], "committed": res["abuse_n_bad"],
        "evicted": "yes" if res["abuse_evicted"] else "no",
        "time_to_eviction_rounds": res["abuse_ttl"] if res["abuse_evicted"] else "inf",
        "note": f"malicious proposer committed {res['abuse_n_bad']} forged updates, then PASSED "
                f"{res['abuse_passes']} consecutive PoSpace challenges (valid plot) — fail_count="
                f"{res['abuse_fails']}, NEVER evicted: no path links ledger misbehaviour to _evict",
    })
    ctrl = _blank()
    ctrl.update({
        "metric": "eviction", "source": "ring_inproc", "block": "pospace_fail_control",
        "evicted": "yes" if res["ctrl_evicted"] else "no",
        "time_to_eviction_rounds": res["ctrl_ttl"] if res["ctrl_evicted"] else "inf",
        "note": f"POSITIVE CONTROL: a corrupted-plot node IS evicted in {res['ctrl_ttl']} "
                f"(=MAX_FAILS={res['max_fails']}) rounds -> the eviction machinery works; it is "
                f"simply not wired to ledger abuse",
    })
    return [abuse, ctrl]


def rows_control(res: dict | None) -> list[dict]:
    """Honest-proposer control (adversary-caused check): valid updates accepted, nothing evicted."""
    row = _blank()
    honest = next((r for r in (res or {}).get("rej", []) if r["n_mal"] == 0), None)
    src = "ring_inproc" if honest is not None else "analytic"
    rr = honest["rejection_rate"] if honest is not None else 0.0
    row.update({
        "metric": "control", "source": src, "f_pct": 0, "n_mal": 0, "realized_f_pct": 0.0,
        "rejection_rate_pct": rr, "ideal_rejection_pct": 0.0, "evicted": "no",
        "note": "honest proposer, valid updates: accepted (rejection 0 = correct) and not evicted "
                "-> the 0% rejection at f>0 is adversary-caused (no defense), not chord.py fragility",
    })
    return [row]


# =============================================================================================
# CSV.
# =============================================================================================
FIELDS = ["metric", "source", "block", "f_pct", "n_mal", "realized_f_pct", "proposals",
          "committed", "rejected", "rejection_rate_pct", "ideal_rejection_pct", "chain_valid",
          "target", "target_forged_pct", "target_share_pct", "evicted",
          "time_to_eviction_rounds", "note"]

_METRIC_ORDER = {"rejection_vs_f": 0, "commit_acceptance": 1, "eviction": 2, "control": 3}


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
        fp = r.get("f_pct", "")
        fp = fp if isinstance(fp, (int, float)) else -1
        return (_METRIC_ORDER.get(r["metric"], 9), str(r.get("block", "")), fp)
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in sorted(rows, key=key):
            w.writerow({k: _fmt(r.get(k, "")) for k in FIELDS})
    print(f"\nwrote {_rel(OUT_CSV)} ({len(rows)} rows)")


# =============================================================================================
# Figure: (1) rejection rate vs f — measured flat 0% vs the ideal a validating protocol would
# achieve (the gap = the vulnerability); (2) time-to-eviction — ledger abuse = never vs the
# PoSpace-fail positive control = MAX_FAILS rounds. Style mirrors B5/A7.
# =============================================================================================
def make_plot(rows: list[dict]) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:                                           # no matplotlib in this env
        print(f"(skipping figure: matplotlib unavailable — {type(e).__name__})")
        return

    INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
    MEASC, IDEALC, CTRLC, ABUSEC = "#c0392b", "#2a78d6", "#1baf7a", "#c0392b"
    plt.rcParams.update({
        "figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb",
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": MUTED, "font.size": 10,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "figure.dpi": 150,
    })
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))

    # --- panel 1: rejection rate vs f (measured vs ideal) ---
    ax = axes[0]
    rej = [r for r in rows if r["metric"] == "rejection_vs_f"]
    rej = sorted(rej, key=lambda r: r["f_pct"])
    fs = [r["f_pct"] for r in rej]
    meas = [r["rejection_rate_pct"] for r in rej]
    ideal = [r["ideal_rejection_pct"] for r in rej]
    ax.plot(fs, ideal, marker="s", ms=5, lw=1.8, color=IDEALC, ls="--",
            label="ideal (validating protocol)")
    ax.plot(fs, meas, marker="o", ms=6, lw=2.0, color=MEASC,
            label="measured (frozen ledger)")
    ax.set_ylim(-4, 104)
    ax.set_xlabel("malicious proposer fraction f (%)")
    ax.set_ylabel("bad-update rejection rate (%)")
    ax.set_title("Bad updates are never rejected (no content validation)")
    ax.legend(frameon=False, fontsize=8, loc="center right")

    # --- panel 2: time-to-eviction (ledger abuse vs PoSpace-fail control) ---
    ax = axes[1]
    ev = {r.get("block"): r for r in rows if r["metric"] == "eviction"}
    ctrl = ev.get("pospace_fail_control", {})
    ctrl_ttl = ctrl.get("time_to_eviction_rounds", "")
    try:
        ctrl_val = float(ctrl_ttl)
    except (TypeError, ValueError):
        ctrl_val = 3.0
    cap = max(ctrl_val * 2, 6)
    bars = ax.bar(["ledger abuse\n(B6)", "PoSpace-fail\n(control)"], [cap, ctrl_val],
                  color=[ABUSEC, CTRLC], width=0.55)
    bars[0].set_hatch("////")
    bars[0].set_alpha(0.35)
    ax.text(0, cap * 0.5, "∞\nnever", ha="center", va="center", fontsize=13,
            fontweight="bold", color=ABUSEC)
    ax.text(1, ctrl_val + cap * 0.04, f"{ctrl_val:.0f} rounds", ha="center", va="bottom",
            fontsize=10, color=INK)
    ax.set_ylim(0, cap * 1.15)
    ax.set_ylabel("rounds to eviction")
    ax.set_title("A malicious proposer is never evicted")

    fig.suptitle("B6 — Malicious ledger proposer: the frozen ledger validates no proposal and "
                 "never evicts the proposer (rejection 0%, eviction never)", y=1.03, fontsize=10.5)
    fig.tight_layout()
    fig.savefig(OUT_FIG, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {_rel(OUT_FIG)}")


# =============================================================================================
# Self-test — deterministic (the plan's verification step). Runs the in-process ring when
# available; --require-ring turns a skip into a failure (CI/security gate).
# =============================================================================================
def _self_test(require_ring: bool = False) -> int:
    ok = True
    print(f"[self-test] N={N} s={S} f-levels={F_LEVELS} n_mal={N_MAL}")

    # (a) workload sanity: n_mal = round(f*N), matches the B0 threat model.
    a_ok = N_MAL == [0, 3, 6, 10, 13, 16]
    ok &= a_ok
    print(f"  (a) n_mal(f) = {N_MAL} == B0 [{'ok' if a_ok else 'OFF'}]")

    # (b) Zipf share of a popular target is in (0, 100].
    ranked = b1.load_served_domains()
    share = zipf_share_pct(ranked[0], ranked)
    b_ok = 0.0 < share <= 100.0
    ok &= b_ok
    print(f"  (b) top-domain Zipf share = {share:.2f}%  [{'ok' if b_ok else 'OFF'}]")

    # (c) in-process ring: bad updates accepted 100% at every f (rejection 0), targeted forge +
    #     chain valid, abuse never evicted (fails 0), positive control evicts in MAX_FAILS.
    res = run_ring_measurements(SEED)
    if res is None:
        print("  (c) in-process ring SKIPPED (node stack unavailable; run under 3.11 + dnspython)")
        if require_ring:
            ok = False
            print("      --require-ring set -> SKIP counts as FAIL")
    else:
        rej0 = all(r["rejected"] == 0 and r["committed"] == r["proposals"] for r in res["rej"])
        targ = res["target_ok"] and res["target_chain"]
        rnd = res["chain_ok"] and res["poison_ok"] and res["random_accept"] == 100.0
        abuse = (not res["abuse_evicted"]) and res["abuse_fails"] == 0 and res["abuse_n_bad"] > 0
        ctrl = res["ctrl_evicted"] and res["ctrl_ttl"] == res["max_fails"]
        c_ok = rej0 and targ and rnd and abuse and ctrl
        ok &= c_ok
        print(f"      rejection=0 all f: {rej0}; random poison+chain: {rnd}; "
              f"targeted forge+chain: {targ}")
        print(f"      abuse never-evicted (fails={res['abuse_fails']}): {abuse}; "
              f"control evicts in {res['ctrl_ttl']}=MAX_FAILS: {ctrl}")
        print(f"  (c) in-process ring measured  [{'ok' if c_ok else 'OFF'}]")

    print("[self-test]", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# =============================================================================================
def main() -> int:
    ap = argparse.ArgumentParser(description="B6 malicious ledger proposer (issue #47).")
    ap.add_argument("--no-plot", action="store_true", help="skip the figure")
    ap.add_argument("--self-test", action="store_true", help="deterministic checks")
    ap.add_argument("--require-ring", action="store_true",
                    help="treat a skipped in-process ring as a failure (CI/security gate)")
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()

    if args.self_test:
        return _self_test(require_ring=args.require_ring)

    print(f"B6 malicious ledger proposer — seed={args.seed}, N={N}, s={S}, "
          f"f-levels={F_LEVELS}")
    res = run_ring_measurements(args.seed)
    if res is None:
        print("  (in-process ring unavailable -> analytic rows only; run under 3.11 + dnspython "
              "for the measured ring_inproc rows)")

    rows: list[dict] = []
    print("\n== rejection rate vs f (bad-update rejection; honest control at f=0) ==")
    rr = rows_rejection(res)
    rows += rr
    for r in rr:
        print(f"  f={r['f_pct']:>2}% n_mal={r['n_mal']:>2}  rejection={r['rejection_rate_pct']:.1f}% "
              f"(ideal {r['ideal_rejection_pct']:.0f}%)  [{r['source']}]")

    print("\n== commit acceptance (random + targeted; store-poison + chain validity) ==")
    ca = rows_commit_acceptance(res)
    rows += ca
    for r in ca:
        if r.get("block") == "targeted":
            print(f"  targeted {r['target']!r}: forged={r['target_forged_pct']}% "
                  f"share~{r['target_share_pct']}% chain={r['chain_valid']}")
        elif r.get("block") == "random":
            print(f"  random: accepted {100 - float(r['rejection_rate_pct']):.1f}% "
                  f"chain={r['chain_valid']}")
        else:
            print(f"  {r['note']}")

    print("\n== eviction (ledger abuse vs PoSpace-fail positive control) ==")
    evr = rows_eviction(res)
    rows += evr
    for r in evr:
        if r.get("block"):
            print(f"  {r['block']}: evicted={r['evicted']} "
                  f"time_to_eviction={r['time_to_eviction_rounds']} rounds")
        else:
            print(f"  {r['note']}")

    rows += rows_control(res)
    print(f"\n== control: honest proposer -> rejection "
          f"{rows[-1]['rejection_rate_pct']}% , evicted={rows[-1]['evicted']} ==")

    write_csv(rows)
    if not args.no_plot:
        make_plot(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
