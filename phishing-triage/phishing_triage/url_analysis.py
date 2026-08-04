"""Heuristic analysis of links found in an email body.

Each `EmailLink` (see `parser.py`) is scored independently against a set of
well-known phishing link patterns: IP-literal hosts, userinfo ("@") host
spoofing, punycode homographs, URL shorteners, abused TLDs, credential-harvest
path keywords, and display-text/href mismatches. None of these individually
prove malice -- a company newsletter legitimately uses bit.ly sometimes -- so
each carries a modest weight and `scoring.py` combines them with everything
else the tool observed.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .brands import is_legit_domain_for_brand, matching_brand
from .parser import EmailLink

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "s.id", "tiny.cc",
}

# TLDs disproportionately used in phishing/scam campaigns, per common industry
# abuse reports. Heuristic only: plenty of legitimate mail uses these too.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "support", "click", "link", "gq", "tk", "ml",
    "cf", "ga", "work", "country", "stream", "icu", "rest", "fit", "cam", "cyou",
}

CREDENTIAL_PATH_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "secure", "account", "update",
    "confirm", "password", "wallet", "unlock", "authenticate", "validate",
}

_DOMAIN_LIKE_RE = re.compile(r"^(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", re.IGNORECASE)


@dataclass(frozen=True)
class UrlFinding:
    href: str
    display_text: str
    host: str
    is_ip_literal: bool = False
    is_userinfo_spoof: bool = False
    is_punycode: bool = False
    is_shortener: bool = False
    suspicious_tld: bool = False
    has_credential_keyword: bool = False
    brand_impersonation: str | None = None
    display_href_mismatch: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)
    weight: int = 0

    def as_dict(self) -> dict:
        return {
            "href": self.href,
            "display_text": self.display_text,
            "host": self.host,
            "is_ip_literal": self.is_ip_literal,
            "is_userinfo_spoof": self.is_userinfo_spoof,
            "is_punycode": self.is_punycode,
            "is_shortener": self.is_shortener,
            "suspicious_tld": self.suspicious_tld,
            "has_credential_keyword": self.has_credential_keyword,
            "brand_impersonation": self.brand_impersonation,
            "display_href_mismatch": self.display_href_mismatch,
            "reasons": list(self.reasons),
            "weight": self.weight,
        }


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _extract_display_host(display_text: str) -> str | None:
    match = _DOMAIN_LIKE_RE.match(display_text.strip())
    return match.group(1).lower() if match else None


def analyze_url(link: EmailLink) -> UrlFinding:
    parsed = urlsplit(link.href)
    host = (parsed.hostname or "").lower()
    reasons: list[str] = []
    weight = 0

    is_ip = _is_ip_literal(host)
    if is_ip:
        reasons.append(f"link host {host!r} is a raw IP address, not a domain name")
        weight += 15

    is_userinfo_spoof = bool(parsed.username)
    if is_userinfo_spoof:
        reasons.append(
            f"link uses userinfo spoofing -- browser navigates to {host!r}, "
            f"but the URL displays {parsed.username!r} before the '@' to look legitimate"
        )
        weight += 25

    is_punycode = "xn--" in host
    if is_punycode:
        reasons.append(f"link host {host!r} uses punycode, a common homograph/lookalike technique")
        weight += 15

    is_shortener = host in SHORTENER_DOMAINS
    if is_shortener:
        reasons.append(f"link uses URL shortener {host!r}, which hides the true destination")
        weight += 8

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    if is_suspicious_tld:
        reasons.append(f"link uses TLD .{tld}, disproportionately associated with abuse")
        weight += 5

    path_lower = parsed.path.lower()
    has_cred_keyword = any(kw in path_lower for kw in CREDENTIAL_PATH_KEYWORDS)
    if has_cred_keyword:
        reasons.append(f"link path {parsed.path!r} contains credential-harvesting keywords")
        weight += 8

    brand_impersonation = None
    brand = matching_brand(host) or matching_brand(link.display_text)
    if brand and not is_legit_domain_for_brand(brand, host):
        brand_impersonation = brand
        reasons.append(
            f"link references brand '{brand}' but host {host!r} is not a known "
            f"{brand} domain"
        )
        weight += 25

    display_href_mismatch = False
    display_host = _extract_display_host(link.display_text)
    if display_host and display_host != host and not host.endswith(f".{display_host}"):
        display_href_mismatch = True
        reasons.append(
            f"displayed link text points to {display_host!r} but the actual href "
            f"goes to {host!r}"
        )
        weight += 20

    return UrlFinding(
        href=link.href,
        display_text=link.display_text,
        host=host,
        is_ip_literal=is_ip,
        is_userinfo_spoof=is_userinfo_spoof,
        is_punycode=is_punycode,
        is_shortener=is_shortener,
        suspicious_tld=is_suspicious_tld,
        has_credential_keyword=has_cred_keyword,
        brand_impersonation=brand_impersonation,
        display_href_mismatch=display_href_mismatch,
        reasons=tuple(reasons),
        weight=weight,
    )


def analyze_links(links: tuple[EmailLink, ...]) -> list[UrlFinding]:
    return [analyze_url(link) for link in links]
