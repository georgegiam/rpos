"""Sub-issue #11 — DNS interface.

A DNSInterfaceMixin that accepts a real DNS query (wire format, parsed with dnspython) and
returns a real DNS response. Answering an A query is delegated to `resolve_name`, a hook
the query path (#12) overrides with the DHT lookup + fallback; the default here answers from
a local record map so the interface can be tested on its own.

Transport is still in-process: in Phase 2 the wire bytes are handed to `handle_dns_query`
directly (and are also reachable as the `dns_query` RPC). Phase 3 puts this behind a UDP socket.
"""
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from node.chord import ChordNode
from node.net import Network

DEFAULT_TTL = 300


def canonical(name: str) -> str:
    """Canonical domain key: lower-case, no trailing dot."""
    return name.rstrip(".").lower()


class DNSInterfaceMixin(ChordNode):
    def __init__(self, pk: bytes, net: Network, **kwargs):
        super().__init__(pk, net, **kwargs)
        self.records: dict[str, tuple[str, int]] = {}     # canonical name -> (ip, ttl)
        self.register("dns_query", self._h_dns_query)

    async def _h_dns_query(self, src, wire: bytes) -> bytes:
        return await self.handle_dns_query(wire)

    async def resolve_name(self, name: str):
        """Return (ip, ttl) for an A record, or None. Overridden by the query path (#12)."""
        return self.records.get(canonical(name))

    async def handle_dns_query(self, wire: bytes) -> bytes:
        """Parse a wire-format DNS query and return a wire-format DNS response."""
        query = dns.message.from_wire(wire)
        response = dns.message.make_response(query)
        if not query.question:
            response.set_rcode(dns.rcode.FORMERR)
            return response.to_wire()

        q = query.question[0]
        qname, qtype = q.name, q.rdtype

        if qtype != dns.rdatatype.A:
            response.set_rcode(dns.rcode.NOTIMP)
            return response.to_wire()

        result = await self.resolve_name(qname.to_text())
        if result is None:
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response.to_wire()

        ip, ttl = result
        answer = dns.rrset.from_text(qname, ttl, "IN", "A", ip)
        response.answer.append(answer)
        response.set_rcode(dns.rcode.NOERROR)
        return response.to_wire()


class DNSNode(DNSInterfaceMixin):
    """Concrete node = Chord + DNS interface (used by tests for this sub-issue)."""
    pass


# ---------- client-side helpers (used by tests and the query generator) ----------
def make_a_query(name: str) -> bytes:
    """Build a wire-format A-record query for `name`."""
    return dns.message.make_query(name, dns.rdatatype.A).to_wire()


def parse_a_response(wire: bytes):
    """Parse a wire response; return (rcode, [ip, ...])."""
    msg = dns.message.from_wire(wire)
    ips = []
    for rrset in msg.answer:
        if rrset.rdtype == dns.rdatatype.A:
            ips.extend(r.address for r in rrset)
    return msg.rcode(), ips
