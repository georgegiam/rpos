"""Test for sub-issue #11 — DNS interface.

Send a real DNS A query (wire format), verify the response parses and matches; also check
NXDOMAIN for an unknown name and NOTIMP for a non-A type.
"""
import asyncio

import dns.message
import dns.rcode
import dns.rdatatype

from node.dns_interface import DNSNode, make_a_query, parse_a_response
from node.net import Network
from node.tests.util import pk_for


async def _run() -> None:
    net = Network()
    node = DNSNode(pk_for(0), net)
    await node.create()
    node.records["example.com"] = ("93.184.216.34", 300)

    # (1) known A record: response parses and matches
    wire_q = make_a_query("example.com")
    wire_r = await node.handle_dns_query(wire_q)
    resp = dns.message.from_wire(wire_r)                 # must parse as a real DNS message
    assert resp.rcode() == dns.rcode.NOERROR
    assert len(resp.answer) == 1
    rr = resp.answer[0]
    assert rr.rdtype == dns.rdatatype.A
    assert rr.ttl == 300
    assert [r.address for r in rr] == ["93.184.216.34"]
    # response ID echoes the query ID (a real response property)
    assert resp.id == dns.message.from_wire(wire_q).id

    rcode, ips = parse_a_response(wire_r)
    assert rcode == dns.rcode.NOERROR and ips == ["93.184.216.34"]

    # (2) unknown name -> NXDOMAIN
    rcode, ips = parse_a_response(await node.handle_dns_query(make_a_query("nope.example.com")))
    assert rcode == dns.rcode.NXDOMAIN and ips == []

    # (3) non-A query -> NOTIMP
    aaaa = dns.message.make_query("example.com", dns.rdatatype.AAAA).to_wire()
    resp = dns.message.from_wire(await node.handle_dns_query(aaaa))
    assert resp.rcode() == dns.rcode.NOTIMP

    node.stop()
    print("test_dns_interface: PASS  (A record matches, NXDOMAIN + NOTIMP correct, IDs echo)")


def test_dns_interface():
    asyncio.run(_run())


if __name__ == "__main__":
    test_dns_interface()
