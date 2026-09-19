"""Sub-issue #12 — query path (Algorithm 2).

resolve_query(domain) implements the resolver's read path:
  1. local cache (unexpired)                          -> outcome "cache_hit"
  2. DHT: fetch from primary + replicas, majority vote -> outcome "dht_hit"
  3. fallback: iterative resolution from a root server, then store the answer back into the
     DHT so later queries hit it                        -> outcome "fallback"

Every query is logged to node/results/queries.csv as
    timestamp, domain, hops, outcome, vote_result.

Builds on StorageMixin (DHT get/put) and DNSInterfaceMixin (resolve_name hook), so a
QueryNode answers real DNS queries through the full path. In-process transport only.
"""
import time

from node.dns_interface import DNSInterfaceMixin, canonical
from node.logs import append_row, now_iso
from node.net import Network
from node.storage import StorageMixin

QUERIES_CSV = "queries.csv"
QUERIES_HEADER = ["timestamp", "domain", "hops", "outcome", "vote_result"]


def _encode(ip: str, ttl: int) -> str:
    return f"{ip}|{ttl}"


def _decode(value: str) -> tuple[str, int]:
    ip, ttl = value.rsplit("|", 1)
    return ip, int(ttl)


class IterativeResolver:
    """Stand-in for the external DNS hierarchy used on a cache/DHT miss.

    Models iterative resolution root -> TLD -> authoritative as a fixed number of referral
    steps over an authoritative zone map. Phase 3 replaces this with a real NSD/BIND world.
    """

    def __init__(self, zone: dict[str, str], ttl: int = 300, steps: int = 3):
        self.zone = {canonical(k): v for k, v in zone.items()}
        self.ttl = ttl
        self.steps = steps

    async def resolve(self, domain: str) -> tuple[str | None, int, int]:
        d = canonical(domain)
        ip = self.zone.get(d)
        return ip, self.ttl, self.steps


class QueryMixin(StorageMixin, DNSInterfaceMixin):
    def __init__(self, pk: bytes, net: Network, upstream: IterativeResolver | None = None, **kwargs):
        super().__init__(pk, net, **kwargs)
        self.upstream = upstream
        self.cache: dict[str, tuple[str, int, float]] = {}   # domain -> (ip, ttl, expiry_monotonic)

    # DNSInterfaceMixin hook -> run the full query path
    async def resolve_name(self, name: str):
        ip, ttl, _outcome, _hops, _vote = await self.resolve_query(name)
        return None if ip is None else (ip, ttl)

    async def resolve_query(self, domain: str):
        """Return (ip, ttl, outcome, hops, vote). Logs one row to queries.csv."""
        d = canonical(domain)

        # 1. cache
        cached = self.cache.get(d)
        if cached is not None and cached[2] > time.monotonic():
            ip, ttl, _ = cached
            self._log(d, 0, "cache_hit", "cache")
            return ip, ttl, "cache_hit", 0, "cache"

        # 2. DHT with majority vote
        value, vote, hops = await self.get_chunk(d)
        if value is not None:
            ip, ttl = _decode(value)
            self.cache[d] = (ip, ttl, time.monotonic() + ttl)
            self._log(d, hops, "dht_hit", vote)
            return ip, ttl, "dht_hit", hops, vote

        # 3. fallback: iterative resolution, then store back into the DHT
        if self.upstream is None:
            self._log(d, hops, "fallback", "nxdomain")
            return None, 0, "fallback", hops, "nxdomain"
        ip, ttl, steps = await self.upstream.resolve(d)
        total_hops = hops + steps
        if ip is None:
            self._log(d, total_hops, "fallback", "nxdomain")
            return None, 0, "fallback", total_hops, "nxdomain"
        written, _ = await self.store_chunk(d, _encode(ip, ttl))
        self.cache[d] = (ip, ttl, time.monotonic() + ttl)
        self._log(d, total_hops, "fallback", f"stored:{len(written)}")
        return ip, ttl, "fallback", total_hops, f"stored:{len(written)}"

    def _log(self, domain: str, hops: int, outcome: str, vote: str) -> None:
        append_row(QUERIES_CSV, QUERIES_HEADER, [now_iso(), domain, hops, outcome, vote])


class QueryNode(QueryMixin):
    """Concrete node = Chord + storage + DNS + query path."""
    pass
