"""URL extraction and lightweight, dependency-free heuristics for phishing triage.

Nothing here makes a network call or a reputation lookup -- everything is a
static, explainable check on the URL string itself: IP-literal hosts, known
shortener domains, punycode/homograph hosts, userinfo ("@") tricks, and
typosquat/impersonation of a small set of commonly-spoofed brand domains.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

URL_RE = re.compile(r"""(?i)\bhttps?://[^\s<>"'\]\)]+""")
HREF_RE = re.compile(r"""(?is)<a\b[^>]*\bhref=["']([^"']+)["'][^>]*>(.*?)</a>""")
TAG_STRIP_RE = re.compile(r"(?s)<[^>]+>")
DOMAIN_LIKE_RE = re.compile(
    r"(?i)(?:https?://)?(?:www\.)?"
    r"([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,})"
)

# Common URL-shortening services, frequently abused to hide the true destination.
KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}

# Frequently-impersonated brand domains. Not exhaustive -- meant to demonstrate
# the technique, easily extended with a longer list or a public brand-abuse feed.
COMMON_BRAND_DOMAINS = [
    "paypal.com",
    "microsoft.com",
    "apple.com",
    "google.com",
    "amazon.com",
    "bankofamerica.com",
    "chase.com",
    "wellsfargo.com",
    "dropbox.com",
    "docusign.com",
    "netflix.com",
    "facebook.com",
    "linkedin.com",
    "americanexpress.com",
    "usps.com",
    "fedex.com",
    "ups.com",
]


@dataclass
class UrlFinding:
    url: str
    host: str
    reasons: list[str]


def defang(url: str) -> str:
    """Render a URL inert for safe inclusion in a report (http[:]// / [.] separators)."""
    return url.replace("://", "[:]//").replace(".", "[.]")


def extract_urls(text: str, html: str) -> list[str]:
    """Return the unique set of URLs found in either body, in first-seen order."""
    seen: dict[str, None] = {}
    for source in (text, html):
        if not source:
            continue
        for match in URL_RE.findall(source):
            url = match.rstrip(".,;:!?")
            seen.setdefault(url, None)
    return list(seen)


def extract_href_text_pairs(html: str) -> list[tuple[str, str]]:
    """Return (href, visible_text) for every anchor tag -- used to catch display-text spoofing,
    e.g. <a href="http://evil.tld">https://paypal.com</a>."""
    if not html:
        return []
    pairs = []
    for href, inner in HREF_RE.findall(html):
        visible = TAG_STRIP_RE.sub("", inner).strip()
        pairs.append((href, visible))
    return pairs


def find_domain_like(text: str) -> str:
    """Find the first domain-looking substring in free text (e.g. anchor display
    text such as "https://paypal.com/login" or bare "paypal.com") and return its
    host, or "" if the text doesn't contain anything domain-shaped."""
    if not text:
        return ""
    match = DOMAIN_LIKE_RE.search(text)
    if not match:
        return ""
    candidate = match.group(0)
    if not candidate.lower().startswith(("http://", "https://")):
        candidate = "http://" + candidate
    return get_host(candidate)


def get_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def is_ip_literal_host(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def is_known_shortener(host: str) -> bool:
    return host in KNOWN_SHORTENERS


def has_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def has_userinfo_trick(url: str) -> bool:
    """Detects the userinfo@host trick, e.g. http://paypal.com@evil.tld/ -- the
    browser navigates to evil.tld, but a skimming reader sees 'paypal.com'."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return "@" in (parsed.netloc or "")


def has_excessive_subdomains(host: str, threshold: int = 4) -> bool:
    return host.count(".") + 1 >= threshold


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


# Digit/letter lookalikes commonly used to squat a brand name (paypa1, micr0soft).
_LEETSPEAK_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def lookalike_brand(host: str, brands: list[str] = COMMON_BRAND_DOMAINS) -> str | None:
    """Return the brand domain a host appears to impersonate, or None if the host is
    that brand's real domain/subdomain, or doesn't resemble any watched brand."""
    if not host:
        return None
    compact_host = host.replace("-", "").replace(".", "")
    normalized_host = compact_host.translate(_LEETSPEAK_MAP)
    # Each hyphen/dot-separated label, checked individually against the brand name so a
    # long compound domain (paypa1-account-verify.com) doesn't dilute the edit distance.
    labels = re.split(r"[.-]", host)

    for brand_domain in brands:
        if host == brand_domain or host.endswith("." + brand_domain):
            return None  # legitimate domain or subdomain of it -- stop checking
        brand_name = brand_domain.split(".")[0]
        if brand_name in compact_host or brand_name in normalized_host:
            return brand_domain
        for label in labels:
            if label and label != "com" and _levenshtein(label, brand_name) <= 2:
                return brand_domain
    return None


def analyze_urls(urls: list[str]) -> list[UrlFinding]:
    """Run every URL through the static heuristics and return only the ones that trip at
    least one, each annotated with the specific reason(s)."""
    results = []
    for url in urls:
        host = get_host(url)
        if not host:
            continue
        reasons: list[str] = []
        if is_ip_literal_host(host):
            reasons.append("IP-literal host")
        if is_known_shortener(host):
            reasons.append("known URL shortener")
        if has_punycode(host):
            reasons.append("punycode (IDN homograph) host")
        if has_userinfo_trick(url):
            reasons.append("userinfo@host obfuscation")
        if has_excessive_subdomains(host):
            reasons.append("excessive subdomains")
        brand = lookalike_brand(host)
        if brand:
            reasons.append(f"looks like it impersonates {brand}")
        if reasons:
            results.append(UrlFinding(url=url, host=host, reasons=reasons))
    return results
