#!/usr/bin/env python3
"""Issue #21 [P3-4] — Zipf query generator for the Phase 3 testbed.

Emits DNS A queries against a resolver following a Zipf(alpha=1.0) popularity distribution
over the testbed's 1000 served domains, and logs one CSV row per query so Phase 6 can compute
latency percentiles, throughput, and success rates.

CSV schema (header written verbatim):

    timestamp,domain,resolver_used,latency_ms,success

  * timestamp    — epoch seconds (float) when the query was sent
  * domain       — the queried name (Zipf-sampled from the served set)
  * resolver_used— label of the target resolver (default "host:port")
  * latency_ms   — wall-clock round-trip in ms (time-to-failure on error/timeout)
  * success      — True/False: got a NOERROR response containing an A record

Done-when:
    python query_gen.py --qps 10 --duration 10 --output /tmp/test.csv

SCOPE (standalone). This is the generator script only; wiring it into the compose network
(replacing the idle `query-gen` placeholder with a Python-capable image) is a separate
follow-up. Run standalone against the Unbound host port published by the testbed
(127.0.0.1:5300, see README) or any resolver via --resolver/--port. If no resolver is
listening (e.g. the done-when smoke run with the testbed down), queries simply fail
(success=False) and a valid CSV is still produced.

Domains (self-contained, matches the zones): read from dns/zones/MANIFEST.json when present
(exact served set, rank order); otherwise reproduce the identical set by importing
read_tranco + select_domains from dns/generate_zones.py with the repo defaults (seed=1,
count=1000, tlds=com,org, vendored Tranco CSV). Sampling is seeded (--seed) for
reproducibility (CLAUDE.md §2).
"""
import argparse
import bisect
import csv
import json
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

HERE = Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE / "dns" / "zones" / "MANIFEST.json"
DEFAULT_TRANCO = HERE / "dns" / "tranco" / "tranco_JZNVY_top100k.csv"
DEFAULT_SEED = 20260919      # repo convention (matches the testbed SEED)
GENERATE_SEED = 1            # generate_zones.py's SEED — used to reproduce the served set


def _import_generate_zones():
    """Import dns/generate_zones.py (reused for read_tranco + select_domains)."""
    sys.path.insert(0, str(HERE / "dns"))
    try:
        import generate_zones
        return generate_zones
    except ImportError as e:                    # pragma: no cover - defensive
        raise SystemExit(f"cannot load domains: dns/generate_zones.py import failed ({e})")


def load_domains(manifest: Path, tranco: Path, count: int) -> list[str]:
    """Return the `count` served domains ordered by real Tranco popularity (rank 1 first).

    The domain *set* comes from dns/zones/MANIFEST.json when present (the exact served set);
    otherwise it is reproduced identically from the vendored Tranco list via
    dns/generate_zones.select_domains, so the generator works on a fresh clone where the
    git-ignored zones/ has not been generated yet.

    Either way the set is ordered by global Tranco rank so the Zipf "most popular" domain is
    the genuinely most popular one — and the ordering is identical regardless of source
    (MANIFEST records are stored alphabetically, which is why we re-rank rather than trust
    dict order).
    """
    gz = _import_generate_zones()

    if manifest.exists():
        with open(manifest) as f:
            records = json.load(f)["records"]
        domain_set = list(records.keys())
        source = manifest.name
    elif tranco.exists():
        ranked = gz.read_tranco(tranco)
        domain_set, _ = gz.select_domains(ranked, ["com", "org"], count)
        source = f"reproduced from {tranco.name}"
    else:
        raise SystemExit(f"cannot load domains: no MANIFEST at {manifest} and no Tranco CSV "
                         f"at {tranco}")

    # Order by global Tranco rank for a meaningful, source-independent popularity ranking.
    if tranco.exists():
        rank = {d: i for i, d in enumerate(gz.read_tranco(tranco))}
        # unranked domains (shouldn't happen — the set is drawn from Tranco) sort to the end
        domains = sorted(domain_set, key=lambda d: rank.get(d, len(rank)))
    else:
        print(f"[warn] {tranco} absent — cannot rank by popularity; using MANIFEST order",
              file=sys.stderr)
        domains = domain_set

    print(f"[info] {len(domains)} domains ({source}), ranked by Tranco popularity",
          file=sys.stderr)
    return domains


class ZipfSampler:
    """Zipf popularity over ranks 1..n: P(rank r) proportional to 1/r**alpha.

    Deterministic given a seeded random.Random. Rank 1 is the most popular domain (first in
    rank order). alpha=1.0 is the classic Zipf used for DNS/web popularity.
    """

    def __init__(self, n: int, alpha: float, rng: random.Random):
        if n <= 0:
            raise ValueError("need at least one domain")
        self._rng = rng
        cum: list[float] = []
        total = 0.0
        for r in range(1, n + 1):
            total += 1.0 / (r ** alpha)
            cum.append(total)
        self._cum = cum
        self._total = total

    def sample(self) -> int:
        """Return a 0-based index into the rank-ordered domain list."""
        x = self._rng.random() * self._total
        return bisect.bisect_left(self._cum, x)


def run_query(resolver: str, port: int, domain: str, timeout: float) -> tuple[float, bool]:
    """Send one A query over UDP. Returns (latency_ms, success).

    success is True only when the response is NOERROR and carries at least one A record;
    timeouts and any other error return (time-to-failure, False).
    """
    query = dns.message.make_query(domain, dns.rdatatype.A)
    start = time.perf_counter()
    try:
        resp = dns.query.udp(query, resolver, port=port, timeout=timeout)
        latency_ms = (time.perf_counter() - start) * 1000.0
        ok = resp.rcode() == dns.rcode.NOERROR and any(
            rr.rdtype == dns.rdatatype.A for rr in resp.answer)
        return latency_ms, ok
    except (dns.exception.Timeout, OSError, dns.exception.DNSException):
        return (time.perf_counter() - start) * 1000.0, False


def main() -> int:
    ap = argparse.ArgumentParser(description="Zipf DNS query generator (issue #21).")
    ap.add_argument("--qps", type=float, required=True, help="queries per second (offered rate)")
    ap.add_argument("--duration", type=float, required=True, help="run length in seconds")
    ap.add_argument("--output", type=Path, required=True, help="CSV output path")
    ap.add_argument("--resolver", default="127.0.0.1",
                    help="resolver IP/host (default 127.0.0.1 — the testbed Unbound host port)")
    ap.add_argument("--port", type=int, default=5300, help="resolver UDP port (default 5300)")
    ap.add_argument("--resolver-name", default=None,
                    help="label for the resolver_used column (default host:port)")
    ap.add_argument("--alpha", type=float, default=1.0, help="Zipf exponent (default 1.0)")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED,
                    help=f"RNG seed for reproducible sampling (default {DEFAULT_SEED})")
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="per-query timeout in seconds (default 5.0)")
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST,
                    help="zones MANIFEST.json (domain source; default dns/zones/MANIFEST.json)")
    ap.add_argument("--tranco", type=Path, default=DEFAULT_TRANCO,
                    help="vendored Tranco CSV (fallback domain source)")
    ap.add_argument("--count", type=int, default=1000,
                    help="number of domains for the Tranco fallback (default 1000)")
    ap.add_argument("--max-workers", type=int, default=64,
                    help="max concurrent in-flight queries (default 64)")
    args = ap.parse_args()

    if args.qps <= 0 or args.duration <= 0:
        ap.error("--qps and --duration must be positive")

    domains = load_domains(args.manifest, args.tranco, args.count)
    sampler = ZipfSampler(len(domains), args.alpha, random.Random(args.seed))
    resolver_label = args.resolver_name or f"{args.resolver}:{args.port}"

    total = int(round(args.qps * args.duration))
    interval = 1.0 / args.qps
    print(f"[info] {len(domains)} domains; sending ~{total} queries at {args.qps} qps "
          f"(~{args.duration}s) to {resolver_label} (alpha={args.alpha}, seed={args.seed})",
          file=sys.stderr)

    rows: list[tuple[float, str, str, float, bool]] = []
    rows_lock = Lock()

    def dispatch(domain: str) -> None:
        sent = time.time()
        latency_ms, ok = run_query(args.resolver, args.port, domain, args.timeout)
        with rows_lock:
            rows.append((sent, domain, resolver_label, latency_ms, ok))

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        for i in range(total):
            domain = domains[sampler.sample()]
            target = t0 + i * interval
            now = time.perf_counter()
            if target > now:
                time.sleep(target - now)
            pool.submit(dispatch, domain)
        # ThreadPoolExecutor.__exit__ waits for all in-flight queries to finish.

    rows.sort(key=lambda r: r[0])   # chronological by send time
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "domain", "resolver_used", "latency_ms", "success"])
        for sent, domain, label, latency_ms, ok in rows:
            w.writerow([f"{sent:.6f}", domain, label, f"{latency_ms:.3f}", ok])

    ok_n = sum(1 for r in rows if r[4])
    print(f"[done] wrote {len(rows)} rows to {args.output} ({ok_n} success, "
          f"{len(rows) - ok_n} failed)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
