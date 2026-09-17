"""IOC extraction and classification: URLs, IPs, and defang/refang helpers.

Findings are defanged (`hxxp://`, `[.]`) before they land in a report, since
IR reports and tickets routinely get copy-pasted into chat tools and ticket
systems that auto-linkify (and sometimes even auto-fetch) raw URLs.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_URL_RE = re.compile(r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>"'()\[\]]+
""")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@lru_cache(maxsize=1)
def _load_json_set(filename: str) -> frozenset[str]:
    path = _DATA_DIR / filename
    with path.open() as fh:
        return frozenset(item.lower() for item in json.load(fh))


def known_url_shorteners() -> frozenset[str]:
    return _load_json_set("url_shorteners.json")


def suspicious_tlds() -> frozenset[str]:
    return _load_json_set("suspicious_tlds.json")


def dangerous_extensions() -> frozenset[str]:
    return _load_json_set("dangerous_extensions.json")


def extract_urls(text: str) -> list[str]:
    """Find http(s)/www URLs in free text, deduplicated, order preserved."""
    seen: dict[str, None] = {}
    for match in _URL_RE.finditer(text or ""):
        url = match.group(0).rstrip(".,;:!?")
        if not url.lower().startswith(("http://", "https://")):
            url = "http://" + url
        seen.setdefault(url, None)
    return list(seen)


def extract_ips(text: str) -> list[str]:
    """Find IPv4 addresses in free text (e.g. Received header chains),
    filtering out anything that doesn't parse as a real address."""
    found: list[str] = []
    for candidate in _IPV4_RE.findall(text or ""):
        try:
            ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        found.append(candidate)
    return found


def defang_url(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def url_domain(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def is_ip_literal_url(url: str) -> bool:
    host = urlparse(url).hostname or ""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_shortener(url: str) -> bool:
    return url_domain(url) in known_url_shorteners()


def has_suspicious_tld(url: str) -> bool:
    domain = url_domain(url)
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    return tld in suspicious_tlds()


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


@dataclass
class AttachmentRisk:
    filename: str
    extension: str
    is_dangerous: bool
    is_double_extension: bool


_EXT_RE = re.compile(r"\.([a-zA-Z0-9]+)$")


def assess_attachment_filename(filename: str) -> AttachmentRisk:
    match = _EXT_RE.search(filename or "")
    ext = match.group(1).lower() if match else ""
    parts = (filename or "").split(".")
    # A "double extension" like invoice.pdf.exe hides the real (dangerous)
    # extension behind a benign-looking one when clients truncate long names.
    double_ext = len(parts) >= 3 and parts[-1].lower() in dangerous_extensions() and parts[-2].lower() not in ("", ext)
    return AttachmentRisk(
        filename=filename,
        extension=ext,
        is_dangerous=ext in dangerous_extensions(),
        is_double_extension=double_ext,
    )
