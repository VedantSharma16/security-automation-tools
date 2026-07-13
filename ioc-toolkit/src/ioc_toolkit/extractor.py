"""Regex-based extraction of indicators of compromise (IOCs) from free text.

Designed for the kind of input an IR/SOC analyst actually has on hand: raw
email headers, vendor threat reports, phishing bodies, log excerpts. Input is
refanged automatically so defanged indicators (``1[.]2[.]3[.]4``,
``hxxp://evil[.]com``) are picked up alongside live ones.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ioc_toolkit.defang import refang

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\)\]]+", re.IGNORECASE)

_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}\b")

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

_IPV6_RE = re.compile(
    r"\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b"
)

_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Last label must be alphabetic (2-24 chars) so we don't mistake dotted
# numeric strings or hashes for domains; requires at least one internal dot.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}\b"
)

IOC_TYPES = (
    "url",
    "email",
    "ipv4",
    "ipv6",
    "sha256",
    "sha1",
    "md5",
    "cve",
    "domain",
)


@dataclass
class IOCMatch:
    ioc_type: str
    value: str


@dataclass
class ExtractionResult:
    matches: list = field(default_factory=list)

    def by_type(self, ioc_type: str) -> list:
        seen = []
        for m in self.matches:
            if m.ioc_type == ioc_type and m.value not in seen:
                seen.append(m.value)
        return seen

    def to_dict(self) -> dict:
        out: dict = {t: [] for t in IOC_TYPES}
        for m in self.matches:
            if m.value not in out[m.ioc_type]:
                out[m.ioc_type].append(m.value)
        return out

    def __len__(self) -> int:
        return len(self.matches)


def _non_overlapping(pattern: re.Pattern, text: str, consumed: list) -> list:
    """Return matches for pattern that don't overlap any (start, end) span
    already in `consumed`, and record their spans in `consumed`."""
    found = []
    for m in pattern.finditer(text):
        span = m.span()
        if any(span[0] < c_end and span[1] > c_start for c_start, c_end in consumed):
            continue
        consumed.append(span)
        found.append(m.group(0))
    return found


def extract(text: str, *, autorefang: bool = True) -> ExtractionResult:
    """Extract IOCs from `text`, in priority order so a single token (e.g. a
    hostname inside a URL) is only ever tagged once, as its most specific
    type."""
    if autorefang:
        text = refang(text)

    consumed: list = []
    result = ExtractionResult()

    def add(ioc_type: str, pattern: re.Pattern) -> None:
        for value in _non_overlapping(pattern, text, consumed):
            result.matches.append(IOCMatch(ioc_type, value))

    # Order matters: more specific / longer matches first so they claim their
    # span before a looser pattern (e.g. domain) can also match a substring.
    add("url", _URL_RE)
    add("email", _EMAIL_RE)
    add("ipv4", _IPV4_RE)
    add("ipv6", _IPV6_RE)
    add("sha256", _SHA256_RE)
    add("sha1", _SHA1_RE)
    add("md5", _MD5_RE)
    add("cve", _CVE_RE)
    add("domain", _DOMAIN_RE)

    # Normalize CVE casing for consistent downstream matching/dedup.
    for m in result.matches:
        if m.ioc_type == "cve":
            m.value = m.value.upper()

    return result
