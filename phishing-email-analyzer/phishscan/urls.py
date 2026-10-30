"""URL extraction and heuristics: lookalikes, IP hosts, shorteners, link/text mismatch."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from .models import Finding

URL_RE = re.compile(r"https?://[^\s<>\"'()]+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "work", "support"}
# Brands commonly impersonated, mapped to their legitimate registrable domain.
BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "office365": "office.com",
    "google": "google.com", "apple": "apple.com", "amazon": "amazon.com",
    "docusign": "docusign.com", "dropbox": "dropbox.com", "netflix": "netflix.com",
    "linkedin": "linkedin.com",
}
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s", "!": "i"})


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []  # (href, visible text)
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def registrable(host: str) -> str:
    """Naive registrable domain (last two labels; handles a few common 2-level TLDs)."""
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in {"co.uk", "com.au", "co.nz", "co.in", "com.br"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)) or bool(re.fullmatch(r"0x[0-9a-f]+", host, re.I))


def extract_urls(text: str, html: str = "") -> list[str]:
    urls = URL_RE.findall(text)
    if html:
        p = _LinkParser()
        p.feed(html)
        urls += [h for h, _ in p.links if h.lower().startswith(("http://", "https://"))]
    seen, out = set(), []
    for u in urls:
        u = u.rstrip(".,;")
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _lookalike(host: str) -> tuple[str, str] | None:
    """Return (brand, legit_domain) if host impersonates a brand it doesn't own."""
    reg = registrable(host)
    if any(reg == legit for legit in BRANDS.values()):
        return None
    normalized = host.lower().translate(_HOMOGLYPHS).replace("-", "")
    for brand, legit in BRANDS.items():
        if brand in normalized:
            return brand, legit
    return None


def analyze_urls(text: str, html: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for url in extract_urls(text, html):
        host = (urlparse(url).hostname or "").lower()
        if not host:
            continue
        if _is_ip(host):
            findings.append(Finding("url", "high", "URL uses a raw IP address", url, "T1566.002"))
        if host in SHORTENERS:
            findings.append(Finding("url", "medium", "URL shortener hides destination", url, "T1566.002"))
        if host.startswith("xn--") or ".xn--" in host:
            findings.append(Finding("url", "high", "Punycode (IDN) hostname, possible homograph attack", url, "T1566.002"))
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            findings.append(Finding("url", "low", "Abuse-prone TLD", url))
        if urlparse(url).username:
            findings.append(Finding("url", "high", "Credentials/userinfo in URL (host spoofing trick)", url, "T1566.002"))
        hit = _lookalike(host)
        if hit:
            findings.append(Finding("url", "high",
                                    f"Domain impersonates {hit[0]} (legit: {hit[1]})", url, "T1566.002"))
        if host.count(".") >= 4:
            findings.append(Finding("url", "low", "Excessive subdomain depth", url))

    if html:
        p = _LinkParser()
        p.feed(html)
        for href, label in p.links:
            m = URL_RE.search(label)
            if m and href.lower().startswith("http"):
                a, b = registrable(urlparse(m.group().rstrip(".,")).hostname or ""), registrable(urlparse(href).hostname or "")
                if a and b and a != b:
                    findings.append(Finding("url", "high", "Link text domain differs from actual href",
                                            f"text={label!r} href={href}", "T1566.002"))
    return findings
