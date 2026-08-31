from __future__ import annotations

import socket
import struct

import pytest

from recon_agent import dns_client


def _question_bytes(domain: str, qtype: int) -> bytes:
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in domain.split("."))
    question += b"\x00"
    question += struct.pack(">HH", qtype, dns_client.QCLASS_IN)
    return question


def _build_response(qid: int, domain: str, qtype: int, answers: list[tuple[int, int, bytes]]) -> bytes:
    """answers: list of (rtype, ttl, rdata) — name always points back at offset 12."""
    flags = 0x8180  # standard response, no error
    header = struct.pack(">HHHHHH", qid, flags, 1, len(answers), 0, 0)
    question = _question_bytes(domain, qtype)

    body = b""
    for rtype, ttl, rdata in answers:
        body += b"\xc0\x0c"  # pointer to name at offset 12
        body += struct.pack(">HHIH", rtype, dns_client.QCLASS_IN, ttl, len(rdata))
        body += rdata

    return header + question + body


class FakeSocket:
    def __init__(self, response: bytes, raise_timeout: bool = False):
        self.response = response
        self.raise_timeout = raise_timeout
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        pass

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def recvfrom(self, bufsize):
        if self.raise_timeout:
            raise socket.timeout("timed out")
        return self.response, ("8.8.8.8", 53)

    def close(self):
        self.closed = True


def test_build_query_encodes_header_and_question():
    packet = dns_client.build_query("example.com", "A", query_id=0x1234)
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", packet[:12])
    assert qid == 0x1234
    assert qd == 1 and an == 0

    expected_question = _question_bytes("example.com", 1)
    assert packet[12:] == expected_question


def test_build_query_rejects_unknown_record_type():
    with pytest.raises(dns_client.DnsError):
        dns_client.build_query("example.com", "BOGUS")


def test_resolve_parses_a_record():
    response = _build_response(0x0001, "example.com", 1, [(1, 300, socket.inet_aton("93.184.216.34"))])
    fake = FakeSocket(response)

    result = dns_client.resolve("example.com", record_type="A", sock=fake)

    assert result.ok
    assert result.records == [dns_client.DnsRecord("example.com", "A", 300, "93.184.216.34")]
    assert fake.closed is False  # caller-supplied socket is not auto-closed


def test_resolve_parses_txt_record_with_multiple_chunks():
    chunk1, chunk2 = b"v=spf1 ", b"include:_spf.example.com ~all"
    rdata = bytes([len(chunk1)]) + chunk1 + bytes([len(chunk2)]) + chunk2
    response = _build_response(2, "example.com", 16, [(16, 300, rdata)])
    fake = FakeSocket(response)

    result = dns_client.resolve("example.com", record_type="TXT", sock=fake)

    assert result.ok
    assert result.records[0].value == "v=spf1 include:_spf.example.com ~all"


def test_resolve_parses_mx_with_name_compression():
    # exchange name reuses the question name via a compression pointer
    rdata = struct.pack(">H", 10) + b"\xc0\x0c"
    response = _build_response(3, "example.com", 15, [(15, 300, rdata)])
    fake = FakeSocket(response)

    result = dns_client.resolve("example.com", record_type="MX", sock=fake)

    assert result.ok
    assert result.records[0].value == "10 example.com"


def test_resolve_returns_error_on_timeout():
    fake = FakeSocket(b"", raise_timeout=True)

    result = dns_client.resolve("example.com", record_type="A", sock=fake)

    assert not result.ok
    assert "timed out" in result.error


def test_resolve_returns_error_on_nxdomain_rcode():
    flags = 0x8183  # rcode 3 = NXDOMAIN
    header = struct.pack(">HHHHHH", 4, flags, 1, 0, 0, 0)
    response = header + _question_bytes("nosuchdomain.example", 1)
    fake = FakeSocket(response)

    result = dns_client.resolve("nosuchdomain.example", record_type="A", sock=fake)

    assert not result.ok
    assert "rcode 3" in result.error
