"""Extraction of indicators of compromise (IOCs) from raw alert/log text.

Handles common analyst conventions such as "defanged" indicators
(e.g. ``185[.]220[.]101[.]1``, ``evil[.]com``, ``hxxps://``) which are
routinely used in tickets and threat-intel write-ups to keep links and
addresses inert.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

CATEGORY_IPV4 = "ipv4"
CATEGORY_DOMAIN = "domain"
CATEGORY_URL = "url"
CATEGORY_EMAIL = "email"
CATEGORY_MD5 = "md5"
CATEGORY_SHA1 = "sha1"
CATEGORY_SHA256 = "sha256"
CATEGORY_CVE = "cve"

_DEFANG_REPLACEMENTS = (
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("[.]", "."),
    ("(.)", "."),
    ("[:]", ":"),
    ("[at]", "@"),
    ("[@]", "@"),
)

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Words that satisfy the domain regex but are almost always false positives
# in alert prose (version strings, filenames, abbreviations).
_DOMAIN_STOPLIST = {"e.g.com", "i.e.com"}

# Restricting matches to known TLDs cuts out most false positives from
# filenames (explorer.exe, schtasks.exe) and dotted names (j.morales) that
# otherwise satisfy the domain shape but aren't domains.
_KNOWN_TLDS = frozenset(
    """com net org io gov edu mil info biz co us uk ca de fr ru cn jp au nl
    br in it es se no fi dk pl ch at be nz ie za mx kr sg hk tw xyz top club
    online site app dev me tv cc ai eu asia name pro mobi tech cloud email
    live world group company network systems solutions services vip icu
    work link click download stream su int coop travel museum aero jobs
    rocks guru ninja pw shop store blog news wiki""".split()
)


def refang(text: str) -> str:
    """Reverse common IOC "defanging" so indicators can be matched reliably."""
    result = text
    for defanged, fanged in _DEFANG_REPLACEMENTS:
        result = result.replace(defanged, fanged)
    return result


@dataclass
class Indicator:
    value: str
    category: str
    context: str = field(default="", repr=False)

    def to_dict(self) -> dict:
        return {"value": self.value, "category": self.category, "context": self.context}


def _context_snippet(text: str, start: int, end: int, radius: int = 40) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    snippet = text[lo:hi].replace("\n", " ").strip()
    return snippet


def extract_iocs(raw_text: str) -> list[Indicator]:
    """Extract deduplicated IOCs from ``raw_text``, refanging first."""
    text = refang(raw_text)
    found: dict[tuple[str, str], Indicator] = {}

    def add(category: str, match: re.Match) -> None:
        value = match.group(0)
        key = (category, value.lower())
        if key not in found:
            found[key] = Indicator(
                value=value,
                category=category,
                context=_context_snippet(text, match.start(), match.end()),
            )

    for match in _URL_RE.finditer(text):
        add(CATEGORY_URL, match)
    for match in _EMAIL_RE.finditer(text):
        add(CATEGORY_EMAIL, match)
    for match in _SHA256_RE.finditer(text):
        add(CATEGORY_SHA256, match)
    for match in _SHA1_RE.finditer(text):
        add(CATEGORY_SHA1, match)
    for match in _MD5_RE.finditer(text):
        add(CATEGORY_MD5, match)
    for match in _CVE_RE.finditer(text):
        add(CATEGORY_CVE, match)
    for match in _IPV4_RE.finditer(text):
        try:
            ipaddress.IPv4Address(match.group(0))
        except ValueError:
            continue
        add(CATEGORY_IPV4, match)
    for match in _DOMAIN_RE.finditer(text):
        value = match.group(0)
        if value.lower() in _DOMAIN_STOPLIST:
            continue
        if (CATEGORY_IPV4, value.lower()) in found:
            continue
        tld = value.rsplit(".", 1)[-1].lower()
        if tld not in _KNOWN_TLDS:
            continue
        add(CATEGORY_DOMAIN, match)

    # Domains embedded in URLs are redundant with the URL indicator itself;
    # keep the domain entry too since analysts often pivot on the bare host.
    return sorted(found.values(), key=lambda i: (i.category, i.value.lower()))
