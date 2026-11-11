"""URL and domain analysis: lookalike/brand-impersonation detection and URL red flags.

Lookalike detection combines three complementary signals against a list of
protected brand domains:

1. **Homoglyph skeletons** - map visually confusable characters (Cyrillic
   ``а``/``е``/``о``, digit swaps like ``0->o`` / ``1->l``, ``rn->m``) to a
   canonical form, so ``pаypal`` (Cyrillic а) and ``paypa1`` both collapse to
   ``paypal``.
2. **Edit distance** - Damerau-Levenshtein distance of 1 catches typosquats
   like ``micorsoft`` or ``gooogle``.
3. **Brand-in-subdomain / combosquatting** - ``paypal.com.account-verify.xyz``
   or ``paypal-secure-login.com`` contain the brand but are registered under a
   different domain.

Registrable-domain extraction uses a small built-in list of multi-label public
suffixes rather than the full Public Suffix List, to stay dependency-free. It
is accurate for common cases; swap in ``tldextract`` for production use.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "edu.au",
    "gov.au", "co.nz", "co.in", "co.jp", "com.br", "com.cn", "com.mx", "co.za",
    "com.sg", "com.tr",
}

CONFUSABLES = {
    # Cyrillic / Greek look-alikes of Latin letters
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h", "ո": "n",
    "α": "a", "ο": "o", "ν": "v", "τ": "t", "κ": "k",
    # Digit / ASCII substitutions
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "!": "i", "|": "l",
}
MULTI_CHAR_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"))

CREDENTIAL_PATH_RE = re.compile(
    r"log-?in|sign-?in|verify|verification|account|secure|update|password|"
    r"auth|webscr|wallet|unlock|suspend|confirm",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class UrlIndicator:
    code: str
    severity: str
    detail: str


def normalize_host(host: str) -> str:
    """Lower-case, strip trailing dot/port, and decode punycode labels to Unicode."""
    host = host.strip().lower().rstrip(".")
    host = host.rsplit("@", 1)[-1].split(":", 1)[0]
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    host = normalize_host(host)
    if is_ip(host):
        return host
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _first_label(domain: str) -> str:
    """The label left of the public suffix (``paypal`` for ``paypal.co.uk``)."""
    return registrable_domain(domain).split(".")[0]


def skeleton(text: str) -> str:
    text = text.lower()
    for multi, single in MULTI_CHAR_CONFUSABLES:
        text = text.replace(multi, single)
    return "".join(CONFUSABLES.get(ch, ch) for ch in text)


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (adjacent transpositions count as 1)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def find_lookalike(host: str, brands: dict[str, list[str]]) -> tuple[str, str] | None:
    """Return ``(brand, technique)`` if ``host`` impersonates a protected brand.

    ``brands`` maps a brand name to its legitimate registrable domains.
    Hosts that are (subdomains of) a legitimate brand domain never match.
    """
    host = normalize_host(host)
    if not host or is_ip(host):
        return None
    reg = registrable_domain(host)
    label = reg.split(".")[0]
    label_skel = skeleton(label)
    # Exact tokens only: "paypal-login" matches "paypal", "pineapple" must not match "apple".
    raw_tokens = {t for t in re.split(r"[.\-_]", host) if t}
    host_tokens = {skeleton(t) for t in raw_tokens}

    for brand, legit_domains in brands.items():
        if reg in legit_domains:
            return None

    for brand, legit_domains in brands.items():
        for legit in legit_domains:
            brand_label = _first_label(legit)
            if label != brand_label and label_skel == skeleton(brand_label):
                technique = "homoglyph" if any(ord(c) > 127 for c in label) else "character substitution"
                return brand, technique
            if len(brand_label) >= 5 and 0 < damerau_levenshtein(label, brand_label) <= 1:
                return brand, "typosquat"
            if skeleton(brand_label) in host_tokens:
                if brand_label in raw_tokens:
                    return brand, "brand name in unrelated domain (combosquatting)"
                return brand, "character substitution + combosquatting"
    return None


def analyze_url(
    href: str,
    display_text: str,
    *,
    brands: dict[str, list[str]],
    shorteners: set[str],
    suspicious_tlds: set[str],
) -> list[UrlIndicator]:
    indicators: list[UrlIndicator] = []
    href = href.strip()
    if href.lower().startswith(("mailto:", "tel:", "#", "cid:")):
        return indicators

    if href.lower().startswith(("data:", "javascript:")):
        return [UrlIndicator("URL-SCHEME", "high", f"Dangerous URL scheme: {href[:40]}")]

    parts = urlsplit(href if "://" in href else "http://" + href)
    netloc = parts.netloc
    host = normalize_host(parts.hostname or "")
    if not host:
        return indicators

    if "@" in netloc:
        indicators.append(UrlIndicator(
            "URL-USERINFO", "high",
            f"URL embeds credentials/userinfo to disguise real host '{host}'"))
    if is_ip(host):
        indicators.append(UrlIndicator("URL-IP", "medium", f"Link points to a raw IP address ({host})"))
    if any(label.startswith("xn--") for label in (parts.hostname or "").split(".")):
        indicators.append(UrlIndicator("URL-PUNYCODE", "medium", f"Punycode (IDN) hostname decodes to '{host}'"))
    reg = registrable_domain(host)
    if reg in shorteners:
        indicators.append(UrlIndicator("URL-SHORTENER", "low", f"URL shortener hides final destination ({reg})"))
    tld = host.rsplit(".", 1)[-1]
    if not is_ip(host) and tld in suspicious_tlds:
        indicators.append(UrlIndicator("URL-TLD", "low", f"Uncommon/abused TLD '.{tld}'"))
    if not is_ip(host) and host.count(".") >= 4:
        indicators.append(UrlIndicator("URL-DEEP-SUBDOMAIN", "low", f"Excessive subdomain depth: {host}"))

    lookalike = find_lookalike(host, brands)
    if lookalike:
        brand, technique = lookalike
        indicators.append(UrlIndicator(
            "URL-LOOKALIKE", "high", f"'{host}' impersonates {brand} via {technique}"))
        if CREDENTIAL_PATH_RE.search(unquote(parts.path + "?" + parts.query)):
            indicators.append(UrlIndicator(
                "URL-CRED-PATH", "medium",
                f"Credential-themed path on impersonating domain: {parts.path or '/'}"))

    # Display text that itself looks like a URL/domain but points elsewhere.
    shown = display_text.strip()
    m = re.search(r"(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})", shown, re.IGNORECASE)
    if m and " " not in shown.strip():
        shown_reg = registrable_domain(m.group(1))
        if shown_reg and shown_reg != reg:
            indicators.append(UrlIndicator(
                "URL-MISMATCH", "high",
                f"Link text shows '{shown_reg}' but actually points to '{reg}'"))
    return indicators
