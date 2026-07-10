"""Extraction of indicators of compromise (IOCs) from free text."""

from __future__ import annotations

import re

_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\b")


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract IPs, URLs, domains, hashes, and emails from text.

    Domains that are actually IP addresses (or hostnames extracted from URLs
    are still reported as domains) are excluded from the domain list.
    """
    ips = _dedup(_IP_RE.findall(text))
    urls = _dedup(_URL_RE.findall(text))
    emails = _dedup(_EMAIL_RE.findall(text))

    ip_set = set(ips)
    candidate_domains = _DOMAIN_RE.findall(text)
    domains = _dedup([d for d in candidate_domains if d not in ip_set])

    # Longer hashes also match as substrings of nothing shorter, but a SHA256
    # will never match the MD5/SHA1 regexes since length differs exactly.
    md5s = _dedup(_MD5_RE.findall(text))
    sha1s = _dedup(_SHA1_RE.findall(text))
    sha256s = _dedup(_SHA256_RE.findall(text))

    return {
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "emails": emails,
        "md5": md5s,
        "sha1": sha1s,
        "sha256": sha256s,
    }
