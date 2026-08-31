"""A minimal, dependency-free DNS client.

Builds and parses raw DNS wire-format messages (RFC 1035) directly with
``struct`` and stdlib sockets — no ``dnspython`` — so the protocol logic is
fully inspectable and testable without any network access (the UDP socket
is injectable).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from random import randint

QTYPES = {"A": 1, "NS": 2, "MX": 15, "TXT": 16, "AAAA": 28}
_QTYPE_NAMES = {v: k for k, v in QTYPES.items()}
QCLASS_IN = 1


class DnsError(Exception):
    """Raised when a DNS query fails or the response can't be parsed."""


@dataclass
class DnsRecord:
    name: str
    rtype: str
    ttl: int
    value: str


@dataclass
class DnsResult:
    domain: str
    record_type: str
    records: list[DnsRecord] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def build_query(domain: str, record_type: str, query_id: int | None = None) -> bytes:
    """Encode a single-question DNS query packet."""
    if record_type not in QTYPES:
        raise DnsError(f"unsupported record type: {record_type}")
    qid = query_id if query_id is not None else randint(0, 0xFFFF)

    flags = 0x0100  # standard query, recursion desired
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)

    question = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in domain.strip(".").split(".")
    )
    question += b"\x00"
    question += struct.pack(">HH", QTYPES[record_type], QCLASS_IN)
    return header + question


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at ``offset``.

    Returns the dotted name and the offset immediately after it in the
    *original* message (i.e. after following any compression pointer, the
    returned offset still reflects where reading should resume).
    """
    labels: list[str] = []
    jumped = False
    resume_at = offset
    steps = 0
    while True:
        steps += 1
        if steps > 128:
            raise DnsError("DNS name decompression exceeded max pointer chain")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                resume_at = offset
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise DnsError("truncated DNS name pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                resume_at = offset + 2
            jumped = True
            offset = pointer
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), resume_at


def parse_response(data: bytes) -> list[DnsRecord]:
    """Parse a DNS response packet into a list of answer records."""
    if len(data) < 12:
        raise DnsError("DNS response shorter than header")

    _, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0x000F
    if rcode != 0:
        raise DnsError(f"DNS server returned rcode {rcode}")

    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        offset += 4  # qtype + qclass

    records: list[DnsRecord] = []
    for _ in range(ancount):
        name, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            raise DnsError("truncated DNS answer record")
        rtype, _rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]

        type_name = _QTYPE_NAMES.get(rtype, str(rtype))
        value = _decode_rdata(type_name, rdata, data, offset)
        records.append(DnsRecord(name=name, rtype=type_name, ttl=ttl, value=value))
        offset += rdlength

    return records


def _decode_rdata(type_name: str, rdata: bytes, full_message: bytes, rdata_offset: int) -> str:
    if type_name == "A" and len(rdata) == 4:
        return socket.inet_ntoa(rdata)
    if type_name == "AAAA" and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if type_name == "NS":
        name, _ = _decode_name(full_message, rdata_offset)
        return name
    if type_name == "MX" and len(rdata) >= 3:
        preference = struct.unpack(">H", rdata[:2])[0]
        exchange, _ = _decode_name(full_message, rdata_offset + 2)
        return f"{preference} {exchange}"
    if type_name == "TXT":
        chunks = []
        pos = 0
        while pos < len(rdata):
            chunk_len = rdata[pos]
            pos += 1
            chunks.append(rdata[pos : pos + chunk_len].decode("utf-8", errors="replace"))
            pos += chunk_len
        return "".join(chunks)
    return rdata.hex()


def resolve(
    domain: str,
    record_type: str = "A",
    server: str = "8.8.8.8",
    port: int = 53,
    timeout: float = 3.0,
    sock: "socket.socket | None" = None,
) -> DnsResult:
    """Resolve ``domain`` for ``record_type`` against ``server``.

    ``sock`` is injectable (any object exposing ``sendto``/``recvfrom``/
    ``settimeout``/``close``) so tests can supply a fake instead of hitting
    the network.
    """
    owns_socket = sock is None
    if sock is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

    try:
        query = build_query(domain, record_type)
        sock.sendto(query, (server, port))
        response, _ = sock.recvfrom(4096)
        records = parse_response(response)
        return DnsResult(domain=domain, record_type=record_type, records=records)
    except (DnsError, OSError, struct.error) as exc:
        return DnsResult(domain=domain, record_type=record_type, error=str(exc))
    finally:
        if owns_socket:
            sock.close()
