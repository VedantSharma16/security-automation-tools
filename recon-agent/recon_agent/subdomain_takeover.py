"""Dangling-CNAME subdomain takeover detection.

A subdomain takeover happens when a DNS CNAME still points at a third-party
service (a GitHub Pages site, an S3 bucket, a Heroku app, ...) after that
resource has been deleted or was never claimed. The subdomain keeps
resolving -- DNS for the third-party's own domain is fine -- but the
provider serves a generic "not found / not claimed" page at that hostname,
and anyone can typically register the same resource name on the provider
and start serving content on the victim's own subdomain. This module checks
each subdomain discovered by `dns_recon.enumerate_subdomains` for exactly
that pattern.

Two network calls are involved, both injectable so the whole module is
testable without touching a real network or DNS server:
  * a raw CNAME lookup (`CnameLookup`) -- stdlib only, no `dnspython`
    dependency, via a small hand-rolled DNS-over-UDP client
  * an HTTP body fetch (`BodyFetcher`) -- checked against a small curated
    set of provider "unclaimed" fingerprints (`data/takeover_fingerprints.json`)
"""

from __future__ import annotations

import json
import os
import socket
import struct
from dataclasses import dataclass
from random import randint
from typing import Callable
from urllib.request import urlopen, Request

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

with open(os.path.join(_DATA_DIR, "takeover_fingerprints.json"), encoding="utf-8") as _fh:
    FINGERPRINTS: list[dict] = json.load(_fh)

DEFAULT_DNS_SERVER = "1.1.1.1"
DNS_PORT = 53
_CNAME_QTYPE = 5
_IN_QCLASS = 1
_BODY_READ_LIMIT = 20_000  # bytes; fingerprints all appear well within this


# --- Minimal DNS-over-UDP client (stdlib only) -------------------------------

def _encode_qname(hostname: str) -> bytes:
    labels = hostname.rstrip(".").split(".")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"


def build_cname_query(hostname: str, query_id: int | None = None) -> tuple[bytes, int]:
    """Build a standard, recursion-desired DNS query for `hostname`'s CNAME record."""
    query_id = randint(0, 0xFFFF) if query_id is None else query_id
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(hostname) + struct.pack(">HH", _CNAME_QTYPE, _IN_QCLASS)
    return header + question, query_id


def _decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at `offset`.

    Returns the dotted name and the offset immediately after it in the
    *original* stream (i.e. after a compression pointer, not after the
    jump target), per RFC 1035 section 4.1.4.
    """
    labels: list[str] = []
    jumps = 0
    cursor = offset
    end_of_name: int | None = None

    while True:
        if jumps > 20:
            raise ValueError("DNS name compression pointer loop")
        length = packet[cursor]
        if length == 0:
            cursor += 1
            if end_of_name is None:
                end_of_name = cursor
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if end_of_name is None:
                end_of_name = cursor + 2
            cursor = pointer
            jumps += 1
            continue
        cursor += 1
        labels.append(packet[cursor:cursor + length].decode("ascii", errors="replace"))
        cursor += length

    return ".".join(labels), end_of_name


def parse_cname_response(packet: bytes) -> str | None:
    """Extract the first CNAME target from a raw DNS response, or None.

    Returns None on NXDOMAIN/NODATA, a malformed packet, or any response
    that simply contains no CNAME record (e.g. the name has only an A
    record) -- all of which just mean "nothing to check further".
    """
    if len(packet) < 12:
        return None
    try:
        _id, _flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", packet[:12])
        offset = 12
        for _ in range(qdcount):
            _name, offset = _decode_name(packet, offset)
            offset += 4  # QTYPE + QCLASS
        for _ in range(ancount):
            _name, offset = _decode_name(packet, offset)
            rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", packet[offset:offset + 10])
            offset += 10
            if rtype == _CNAME_QTYPE:
                target, _ = _decode_name(packet, offset)
                return target.rstrip(".") or None
            offset += rdlength
    except (struct.error, IndexError, ValueError):
        return None
    return None


CnameLookup = Callable[[str, float], "str | None"]


def default_cname_lookup(hostname: str, timeout: float = 3.0, server: str = DEFAULT_DNS_SERVER) -> str | None:
    query, query_id = build_cname_query(hostname)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (server, DNS_PORT))
        response, _addr = sock.recvfrom(4096)
    if len(response) < 2 or struct.unpack(">H", response[:2])[0] != query_id:
        return None
    return parse_cname_response(response)


# --- HTTP body fetch for fingerprint matching --------------------------------

BodyFetcher = Callable[[str, float], "tuple[int | None, str]"]


def default_body_fetcher(url: str, timeout: float) -> tuple[int | None, str]:
    request = Request(url, headers={"User-Agent": "recon-agent/0.1 (authorized-assessment)"})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - deliberate recon request
        body = response.read(_BODY_READ_LIMIT).decode(errors="replace")
        return response.status, body


def _match_provider(cname: str) -> dict | None:
    cname_lower = cname.rstrip(".").lower()
    for provider in FINGERPRINTS:
        for suffix in provider["cname_suffixes"]:
            if cname_lower.endswith(suffix.lower()):
                return provider
    return None


@dataclass(frozen=True)
class TakeoverCandidate:
    subdomain: str
    cname: str | None
    provider: str | None
    vulnerable: bool
    evidence: str

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "cname": self.cname,
            "provider": self.provider,
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
        }


def check_takeover(
    subdomain: str,
    cname_lookup: CnameLookup = default_cname_lookup,
    body_fetcher: BodyFetcher = default_body_fetcher,
    timeout: float = 3.0,
) -> TakeoverCandidate:
    """Check a single subdomain for a dangling-CNAME takeover risk.

    Only flags `vulnerable=True` when the CNAME points at a recognized
    third-party provider AND (the provider's own "unclaimed" fingerprint is
    present in the response body, OR the connection to that provider fails
    outright -- both are the two ways a dangling CNAME actually presents).
    A CNAME to an unrecognized host, or a live/claimed resource, is not
    flagged; this keeps the check conservative and low-false-positive.
    """
    try:
        cname = cname_lookup(subdomain, timeout)
    except OSError as exc:
        return TakeoverCandidate(subdomain, None, None, False, f"CNAME lookup failed: {exc}")

    if not cname:
        return TakeoverCandidate(subdomain, None, None, False, "No CNAME record found; not a candidate for dangling-CNAME takeover.")

    provider = _match_provider(cname)
    if not provider:
        return TakeoverCandidate(subdomain, cname, None, False, f"CNAME points to {cname}, which does not match a known vulnerable-provider fingerprint.")

    name = provider["provider"]
    try:
        _status, body = body_fetcher(f"https://{subdomain}/", timeout)
    except Exception as exc:
        return TakeoverCandidate(
            subdomain, cname, name, True,
            f"CNAME points to unclaimed-looking {name} resource ({cname}); connection failed ({exc}), "
            "consistent with a dangling reference to a deprovisioned endpoint.",
        )

    for fingerprint in provider["fingerprints"]:
        if fingerprint.lower() in body.lower():
            return TakeoverCandidate(
                subdomain, cname, name, True,
                f"CNAME points to {cname} ({name}); response body matches the provider's "
                f"\"unclaimed resource\" fingerprint ({fingerprint!r}). Likely takeover-able.",
            )

    return TakeoverCandidate(subdomain, cname, name, False, f"CNAME points to a {name} resource ({cname}) that appears live/claimed.")
