"""Extract indicators of compromise (IOCs) from free-form incident text.

Handles analyst-style defanging (``185[.]220[.]101[.]45``, ``hxxps://``,
``example[.]com``) and filters a few common false-positive shapes (private/
loopback IPs are kept but labeled, not dropped, since they're often exactly
what an IR analyst needs to see).
"""

from __future__ import annotations

import ipaddress
import re

_DEFANG_SUBS = [
    (re.compile(r"\[\.\]|\(\.\)"), "."),
    (re.compile(r"hxxps://", re.IGNORECASE), "https://"),
    (re.compile(r"hxxp://", re.IGNORECASE), "http://"),
    (re.compile(r"\[://\]|\[:\]//"), "://"),
]

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|info|biz|ru|cn|top|xyz|club|online|site|link|dev|app)\b",
    re.IGNORECASE,
)
_HASH_RES = {
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_FILENAME_TLD_TRAP = re.compile(
    r"\.(?:exe|dll|sys|log|txt|conf|cfg|ini|py|sh|json|yaml|yml|zip|tar|gz)$", re.IGNORECASE
)


def refang(text: str) -> str:
    """Reverse common analyst defanging conventions so regexes can match normally."""
    for pattern, replacement in _DEFANG_SUBS:
        text = pattern.sub(replacement, text)
    return text


def _is_private_or_reserved(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def extract_iocs(text: str) -> dict:
    """Extract IOCs from ``text``, returning categorized, de-duplicated lists.

    Returns a dict with keys: ips, domains, urls, emails, hashes, cves. Each IP
    entry is a dict noting whether it's a private/reserved address.
    """
    clean = refang(text)

    raw_urls = _URL_RE.findall(clean)
    urls = sorted({url.rstrip(".,;:)]}'\"") for url in raw_urls})

    # Extract domains from URLs too, so a domain-only IOC list stays complete.
    domain_candidates = set(_DOMAIN_RE.findall(clean))
    for url in urls:
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        if _DOMAIN_RE.fullmatch(host):
            domain_candidates.add(host)
    domains = sorted(d for d in domain_candidates if not _FILENAME_TLD_TRAP.search(d))

    ips = []
    for ip in sorted(set(_IPV4_RE.findall(clean))):
        ips.append({"value": ip, "private_or_reserved": _is_private_or_reserved(ip)})

    emails = sorted(set(_EMAIL_RE.findall(clean)))

    hashes = []
    seen_hash_values = set()
    for algo, pattern in _HASH_RES.items():
        for match in pattern.findall(clean):
            key = match.lower()
            if key in seen_hash_values:
                continue
            seen_hash_values.add(key)
            hashes.append({"value": match, "algorithm": algo})

    cves = sorted({c.upper() for c in _CVE_RE.findall(clean)})

    return {
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "emails": emails,
        "hashes": hashes,
        "cves": cves,
    }


def total_indicator_count(indicators: dict) -> int:
    return (
        len(indicators.get("ips", []))
        + len(indicators.get("domains", []))
        + len(indicators.get("urls", []))
        + len(indicators.get("emails", []))
        + len(indicators.get("hashes", []))
        + len(indicators.get("cves", []))
    )
