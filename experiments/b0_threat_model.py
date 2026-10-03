#!/usr/bin/env python3
"""B0 — Experimental threat model (issue #41, Phase 7, examiner point (ii)).

Single source of truth for the Phase-7 attack matrix. Running this script regenerates
``results/B0_threat_model.csv`` deterministically (no measurement, no RNG) from the
``MATRIX`` table below. The human-readable companion is ``results/B0_threat_model.md``,
which renders the same rows plus the mapping to thesis Tables 4.1 / 4.2 and the
experiment-cell enumeration.

B0 is a *design* deliverable, not a testbed run: it frames every later attack experiment
(B1–B7) with the adversary dimensions the examiners asked for — adversary fraction f,
colluding vs independent, random vs targeted placement — and ties each attack to a row of
the thesis threat tables. No frozen artifact is touched (this file imports nothing from the
protocol; the ``hook``/``malicious_mode`` columns merely *name* the handlers in
``node/malicious.py``).

Frozen parameters for every B-run (results/PARAMETERS.md): N=32, s=3, δ=2 s, netem 5/50 ms,
seed 20260919. n_malicious_at_N32 = round(f · 32).
"""
from __future__ import annotations

import csv
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT_CSV = os.path.join(REPO, "results", "B0_threat_model.csv")

# Adversary-fraction grid (examiner spec) and its integer realisation at the frozen N=32 ceiling.
F_PCT = [0, 10, 20, 30, 40, 50]
N_EMU = 32
F_VALUES_PCT = ",".join(str(f) for f in F_PCT)                       # "0,10,20,30,40,50"
N_MAL_AT_N32 = ",".join(str(round(f / 100 * N_EMU)) for f in F_PCT)  # "0,3,6,10,13,16"

FIELDS = [
    "attack_id", "attack_name", "malicious_mode", "hook",
    "f_values_pct", "n_malicious_at_N32", "collusion", "placement",
    "metric", "defense_tested", "thesis_table", "thesis_row",
    "code_status", "note",
]

# One row per attack B1–B7 (tidy long-format, matching the A-series deliverables).
# thesis_row references the verbatim rows pasted from the external thesis Tables 4.1 / 4.2.
MATRIX = [
    {
        "attack_id": "B1",
        "attack_name": "Tampering / poisoning",
        "malicious_mode": "lie",
        "hook": "_h_get_chunk (node/storage.py)",
        "f_values_pct": F_VALUES_PCT,
        "n_malicious_at_N32": N_MAL_AT_N32,
        "collusion": "both",
        "placement": "both",
        "metric": "% forged answers accepted vs majority-vote bound (needs > s/2 replicas lying)",
        "defense_tested": "s-replica majority vote (node/storage.py)",
        "thesis_table": "4.1",
        "thesis_row": "4.1 Integrity: Cache poisoning; Forged responses",
        "code_status": "behaviour plumbed; needs driver",
        "note": "colluding+targeted (co-located on one chunk's replica set) is the case that can cross the vote bound",
    },
    {
        "attack_id": "B2",
        "attack_name": "Targeted placement / ID grinding",
        "malicious_mode": "n/a (strategy) + lie",
        "hook": "node-ID choice at join; then _h_get_chunk",
        "f_values_pct": "n/a (cost axis)",
        "n_malicious_at_N32": "n/a",
        "collusion": "colluding",
        "placement": "targeted",
        "metric": "cost to own ceil((s+1)/2) of a target chunk's replicas; can node IDs be ground?",
        "defense_tested": "consistent-hash ID placement + PoSpace admission (grind resistance)",
        "thesis_table": "4.1",
        "thesis_row": "4.1 Availability: Eclipse attack; Censorship: Consensus manipulation",
        "code_status": "needs new code (ID-grinding strategy)",
        "note": "underpins the targeted variant of B1/B6; grinding is resisted if id=H(pk) and a valid pk needs a real plot (ties to 4.2 Sybil)",
    },
    {
        "attack_id": "B3",
        "attack_name": "Censorship",
        "malicious_mode": "drop",
        "hook": "_should_drop (node/net.py, node/socket_net.py)",
        "f_values_pct": F_VALUES_PCT,
        "n_malicious_at_N32": N_MAL_AT_N32,
        "collusion": "both",
        "placement": "both",
        "metric": "resolution success rate + latency for blocked (targeted) domains",
        "defense_tested": "replication (s) + iterative fallback (node/query.py)",
        "thesis_table": "4.1",
        "thesis_row": "4.1 Censorship: Selective blocking; Indirect/adaptive",
        "code_status": "behaviour plumbed; needs driver",
        "note": "targeted = specific/popular domains' replicas; fallback recovers unless all s replicas AND upstream are blocked",
    },
    {
        "attack_id": "B4",
        "attack_name": "Routing / eclipse",
        "malicious_mode": "misroute (+ drop)",
        "hook": "_h_find_successor, _h_closest_preceding (node/chord.py)",
        "f_values_pct": F_VALUES_PCT,
        "n_malicious_at_N32": N_MAL_AT_N32,
        "collusion": "colluding",
        "placement": "both",
        "metric": "lookup success rate + extra hops",
        "defense_tested": "finger + successor-list redundancy (node/chord.py)",
        "thesis_table": "4.1",
        "thesis_row": "4.1 Availability: Eclipse attack; Partitioning",
        "code_status": "behaviour plumbed; needs driver",
        "note": "targeted = surround one key's neighbourhood (eclipse); random misroute is the baseline",
    },
    {
        "attack_id": "B5",
        "attack_name": "Sybil",
        "malicious_mode": "n/a (strategy) + forge",
        "hook": "PoSpace admission path (node/pospace_admission.py)",
        "f_values_pct": "n/a (storage-budget axis)",
        "n_malicious_at_N32": "n/a",
        "collusion": "colluding",
        "placement": "both",
        "metric": "# admitted identities and chunk control per unit storage budget",
        "defense_tested": "PoSpace v3-DRG admission (node/pospace_admission.py)",
        "thesis_table": "4.2",
        "thesis_row": "4.2 Integrity/Fairness: Sybil attack (also Amortisation)",
        "code_status": "needs new code (Sybil-budget driver)",
        "note": "PoSpace is the intended Sybil defense; axis is storage budget, not f; amortisation/rationality cheats are Phase 1 + Phase 8 (C-series)",
    },
    {
        "attack_id": "B6",
        "attack_name": "Malicious proposer",
        "malicious_mode": "forge (+ ledger abuse, new)",
        "hook": "_h_challenge (node/pospace_admission.py); ledger propose (node/ledger.py, new)",
        "f_values_pct": F_VALUES_PCT,
        "n_malicious_at_N32": N_MAL_AT_N32,
        "collusion": "colluding",
        "placement": "both",
        "metric": "bad-update rejection rate + time to eviction",
        "defense_tested": "2PC majority commit (node/ledger.py) + consensus eviction (deferred)",
        "thesis_table": "both",
        "thesis_row": "4.1 Censorship: Consensus manipulation + Integrity; 4.2 Rationality (fabricated proof)",
        "code_status": "behaviour plumbed (forge); needs new code (ledger proposer + consensus eviction)",
        "note": "consensus eviction was explicitly deferred to Phase 7 (node/pospace_admission.py docstring)",
    },
    {
        "attack_id": "B7",
        "attack_name": "Denial of service",
        "malicious_mode": "drop (black-hole / flood)",
        "hook": "_should_drop (node/net.py, node/socket_net.py)",
        "f_values_pct": F_VALUES_PCT,
        "n_malicious_at_N32": N_MAL_AT_N32,
        "collusion": "both",
        "placement": "both",
        "metric": "honest-query success rate + latency under attack (effect on everyone else)",
        "defense_tested": "redundancy (replication + routing); no dedicated DoS defense",
        "thesis_table": "4.1",
        "thesis_row": "4.1 Availability: DoS; Partitioning",
        "code_status": "behaviour plumbed; needs driver",
        "note": "metric is measured on the honest nodes, not the attackers",
    },
]


def write_csv(path: str = OUT_CSV) -> None:
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for row in MATRIX:
            missing = set(FIELDS) - set(row)
            if missing:
                raise ValueError(f"{row['attack_id']} missing fields: {sorted(missing)}")
            w.writerow(row)


def main() -> None:
    write_csv()
    print(f"wrote {OUT_CSV} ({len(MATRIX)} attacks, {len(FIELDS)} columns)")
    print(f"f grid: {F_VALUES_PCT} %  ->  n_malicious at N={N_EMU}: {N_MAL_AT_N32}")


if __name__ == "__main__":
    main()
