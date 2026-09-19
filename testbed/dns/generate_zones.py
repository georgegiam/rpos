#!/usr/bin/env python3
"""Issue #18 [P3-1] — generate the containerized DNS hierarchy's zone files.

Deterministic, fixed-seed generator for a 5-server authoritative hierarchy:

    root (.)  ->  com. / org. (2 TLDs)  ->  auth1 / auth2 (per-domain zones)

The referral chain is real: the root delegates to the TLD servers, each TLD delegates every
domain to one of the two authoritative servers (NS + in-bailiwick glue at every hop), and only
the authoritative servers hold the A records. This is what the thesis resolver's fallback
(node/query.py IterativeResolver, currently a stub) will iterate over in a later issue.

Everything is reconstructible bit-for-bit from public inputs (CLAUDE.md §2): domains come from
the vendored Tranco snapshot in rank order, answer IPs are a pure function of a domain's index,
the auth split is sha256(domain) % 2, and TTLs are drawn from a single seeded RNG. Run twice
and `diff -r` the outputs — they are identical.

Stdlib only. Usage:

    python generate_zones.py --count 1000
    diff -r <(...) ...   # see README / verify.sh

Outputs under --out (default ./zones): root/, com/, org/, auth1/, auth2/ zone files,
zones.auth1.conf / zones.auth2.conf (NSD includes), and MANIFEST.json.
"""
import argparse
import csv
import hashlib
import json
import random
import sys
from pathlib import Path

SEED = 1  # repo convention (phase1/*.py); overridable with --seed
SOA_SERIAL = 2026091900  # fixed => reproducible; bump only on an intentional zone change
TTL_LADDER = [300, 600, 900, 1800, 3600]  # realistic discrete TTLs, all within 300-3600s
INFRA_TTL = 3600  # TTL for root/TLD infrastructure records

HERE = Path(__file__).resolve().parent
DEFAULT_TRANCO = HERE / "tranco" / "tranco_JZNVY_top100k.csv"
DEFAULT_TOPOLOGY = HERE / "topology.json"


def load_topology(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def read_tranco(path: Path) -> list[str]:
    """Return domains in rank order from a Tranco 'rank,domain' CSV (no header)."""
    domains = []
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if len(row) >= 2 and row[1]:
                domains.append(row[1].strip().lower())
    return domains


def fetch_tranco(list_id: str, dest: Path, top: int = 100000) -> None:
    """Opt-in (--fetch-list): re-download a pinned Tranco list. Not on the default path."""
    import urllib.request
    url = f"https://tranco-list.eu/download/{list_id}/{top}"
    print(f"[fetch] {url} -> {dest}", file=sys.stderr)
    dest.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, dest)


def select_domains(ranked: list[str], tlds: list[str], count: int) -> tuple[list[str], dict]:
    """Pick `count` domains: top count/N per TLD in rank order; fill any shortfall from the
    first TLD's remainder. Returns (selected_in_order, stats)."""
    per_tld = count // len(tlds)
    by_tld: dict[str, list[str]] = {t: [] for t in tlds}
    seen: set[str] = set()
    for d in ranked:
        suffix = d.rsplit(".", 1)[-1]
        if suffix in by_tld and d not in seen:
            by_tld[suffix].append(d)
            seen.add(d)

    selected: list[str] = []
    chosen: set[str] = set()
    shortfall = 0
    for t in tlds:
        take = by_tld[t][:per_tld]
        selected.extend(take)
        chosen.update(take)
        if len(take) < per_tld:
            shortfall += per_tld - len(take)

    # fill remainder (rounding + any per-TLD shortfall) from leftovers, rank order across TLDs
    if len(selected) < count:
        for t in tlds:
            for d in by_tld[t]:
                if len(selected) >= count:
                    break
                if d not in chosen:
                    selected.append(d)
                    chosen.add(d)

    stats = {
        "requested": count,
        "selected": len(selected),
        "per_tld_target": per_tld,
        "available_per_tld": {t: len(by_tld[t]) for t in tlds},
        "org_or_secondary_shortfall_filled_from_primary": shortfall,
    }
    if shortfall:
        print(f"[warn] {shortfall} domain(s) short in secondary TLD(s); filled from the "
              f"primary TLD (recorded in MANIFEST.json)", file=sys.stderr)
    return selected, stats


def answer_ip(i: int) -> str:
    """Deterministic synthetic A-record target for the i-th selected domain (1-based).
    Private 10.0.0.0/8 range, disjoint from the 172.28.0.0/24 infra subnet. Never routed."""
    return f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"


def auth_of(domain: str) -> str:
    """Deterministic, seed-independent auth assignment."""
    h = int(hashlib.sha256(domain.encode()).hexdigest(), 16)
    return "auth1" if h % 2 == 0 else "auth2"


def soa(mname: str, rname: str, minimum: int) -> str:
    return (f"@\tIN SOA {mname} {rname} ( {SOA_SERIAL} "
            f"3600 900 604800 {minimum} )")


def write_root_zone(out: Path, topo: dict, tlds: list[str]) -> None:
    s = topo["servers"]
    lines = [f"$TTL {INFRA_TTL}", "$ORIGIN .",
             soa(s["root"]["ns_name"], "admin.root.", INFRA_TTL),
             f"@\tIN NS {s['root']['ns_name']}",
             f"{s['root']['ns_name']}\tIN A {s['root']['ip']}"]
    for t in tlds:
        lines.append(f"{t}.\tIN NS {s[t]['ns_name']}")
        lines.append(f"{s[t]['ns_name']}\tIN A {s[t]['ip']}")
    (out / "root").mkdir(parents=True, exist_ok=True)
    (out / "root" / "root.zone").write_text("\n".join(lines) + "\n")


def write_tld_zone(out: Path, topo: dict, tld: str, domains: list[str],
                   assign: dict[str, str]) -> None:
    s = topo["servers"]
    ns = s[tld]["ns_name"]
    lines = [f"$TTL {INFRA_TTL}", f"$ORIGIN {tld}.",
             soa(ns, f"admin.{tld}.", INFRA_TTL),
             f"@\tIN NS {ns}",
             f"ns\tIN A {s[tld]['ip']}"]
    for d in domains:
        label = d[: -(len(tld) + 1)]  # strip trailing ".com" / ".org"
        auth = assign[d]
        lines.append(f"{label}\tIN NS ns1.{d}.")
        lines.append(f"ns1.{label}\tIN A {s[auth]['ip']}")  # in-bailiwick glue
    (out / tld).mkdir(parents=True, exist_ok=True)
    (out / tld / f"{tld}.zone").write_text("\n".join(lines) + "\n")


def write_auth_zone(out: Path, topo: dict, domain: str, auth: str, ip: str, ttl: int) -> None:
    auth_ip = topo["servers"][auth]["ip"]
    ns = f"ns1.{domain}."
    lines = [f"$TTL {ttl}", f"$ORIGIN {domain}.",
             soa(ns, f"admin.{domain}.", ttl),
             f"@\tIN NS {ns}",
             f"ns1\tIN A {auth_ip}",
             f"@\tIN A {ip}",
             f"www\tIN A {ip}"]
    (out / auth).mkdir(parents=True, exist_ok=True)
    (out / auth / f"{domain}.zone").write_text("\n".join(lines) + "\n")


def write_nsd_includes(out: Path, auth_zones: dict[str, list[str]]) -> None:
    for auth, doms in auth_zones.items():
        blocks = []
        for d in doms:
            blocks.append(f'zone:\n\tname: "{d}."\n\tzonefile: "{auth}/{d}.zone"')
        (out / f"zones.{auth}.conf").write_text("\n".join(blocks) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate the DNS-hierarchy zone files (issue #18).")
    ap.add_argument("--count", type=int, default=1000, help="number of domains (default 1000)")
    ap.add_argument("--tlds", default="com,org", help="comma-separated TLDs (default com,org)")
    ap.add_argument("--tranco", type=Path, default=DEFAULT_TRANCO, help="vendored Tranco CSV")
    ap.add_argument("--topology", type=Path, default=DEFAULT_TOPOLOGY, help="topology.json")
    ap.add_argument("--out", type=Path, default=HERE / "zones", help="output dir (default ./zones)")
    ap.add_argument("--seed", type=int, default=SEED, help=f"RNG seed (default {SEED})")
    ap.add_argument("--synthetic-tld", action="store_true",
                    help="(escape hatch) mint synthetic .test names instead of real Tranco domains")
    ap.add_argument("--fetch-list", metavar="ID",
                    help="(opt-in) re-download Tranco list ID to --tranco before generating")
    args = ap.parse_args()

    tlds = [t.strip().lower() for t in args.tlds.split(",") if t.strip()]
    topo = load_topology(args.topology)

    if args.fetch_list:
        fetch_tranco(args.fetch_list, args.tranco)

    if args.synthetic_tld:
        per = args.count // len(tlds)
        ranked = [f"example{i:06d}.{t}" for t in tlds for i in range(per + 5)]
    else:
        ranked = read_tranco(args.tranco)

    selected, stats = select_domains(ranked, tlds, args.count)

    rng = random.Random(args.seed)
    assign: dict[str, str] = {}
    records: dict[str, dict] = {}
    auth_zones: dict[str, list[str]] = {"auth1": [], "auth2": []}
    per_tld_selected: dict[str, list[str]] = {t: [] for t in tlds}

    for i, d in enumerate(selected, start=1):
        tld = d.rsplit(".", 1)[-1]
        auth = auth_of(d)
        ttl = rng.choice(TTL_LADDER)
        ip = answer_ip(i)
        assign[d] = auth
        auth_zones[auth].append(d)
        per_tld_selected[tld].append(d)
        records[d] = {"tld": tld, "auth": auth, "answer_ip": ip,
                      "ns_ip": topo["servers"][auth]["ip"], "ttl": ttl}

    # write zones
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    write_root_zone(out, topo, tlds)
    for t in tlds:
        write_tld_zone(out, topo, t, per_tld_selected[t], assign)
    for d, rec in records.items():
        write_auth_zone(out, topo, d, rec["auth"], rec["answer_ip"], rec["ttl"])
    write_nsd_includes(out, auth_zones)

    # tranco fingerprint for the manifest
    tranco_sha = ""
    if args.tranco.exists():
        tranco_sha = hashlib.sha256(args.tranco.read_bytes()).hexdigest()

    manifest = {
        "seed": args.seed,
        "count": args.count,
        "tlds": tlds,
        "soa_serial": SOA_SERIAL,
        "tranco_file": args.tranco.name,
        "tranco_sha256": tranco_sha,
        "synthetic_tld": args.synthetic_tld,
        "selection": stats,
        "auth_counts": {a: len(z) for a, z in auth_zones.items()},
        "servers": {k: v["ip"] for k, v in topo["servers"].items()},
        "records": records,
    }
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(f"[ok] {len(selected)} domains -> {out}  "
          f"(auth1={len(auth_zones['auth1'])}, auth2={len(auth_zones['auth2'])})")
    print(f"[ok] MANIFEST.json written; run verify.sh after `docker compose up`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
