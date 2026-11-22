"""Domain helpers: registrable-domain extraction and lookalike/brand-spoof detection.

No Public Suffix List download is required: a small built-in set of common
multi-label suffixes covers the cases that matter for triage, and the
functions degrade gracefully (treating the last two labels as registrable)
for anything else.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "edu.au",
    "gov.au", "co.nz", "co.in", "co.jp", "com.br", "com.cn", "com.sg", "co.za",
}

# Visual confusables collapsed to a canonical "skeleton" (subset of Unicode TR39
# plus the classic ASCII swaps attackers use in typosquats).
_CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l",
    # Cyrillic / Greek lookalikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "ν": "v", "α": "a", "ο": "o",
    "ρ": "p", "τ": "t", "κ": "k", "ı": "i", "ӏ": "l",
}
_MULTI_CHAR_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("i", "l"))


def to_unicode(domain: str) -> str:
    """Decode punycode (xn--) labels so homoglyph checks see the real characters."""
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return domain


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    host = host.lower().strip(".")
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _label(domain: str) -> str:
    """The brand-bearing label: 'paypal' for 'paypal.com', 'commbank' for 'commbank.com.au'."""
    return registrable_domain(domain).split(".")[0]


def skeleton(text: str) -> str:
    s = "".join(_CONFUSABLES.get(ch, ch) for ch in text.lower())
    for src, dst in _MULTI_CHAR_CONFUSABLES:
        s = s.replace(src, dst)
    return s.replace("-", "")


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (adjacent transpositions count as one edit)."""
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
    return d[-1][-1]


@lru_cache(maxsize=1)
def load_brands() -> dict[str, dict]:
    with resources.files("phishtriage.data").joinpath("brands.json").open(encoding="utf-8") as fh:
        return json.load(fh)["brands"]


def brand_for_domain(domain: str) -> str | None:
    """Return the brand that legitimately owns ``domain`` (or a parent of it), if any."""
    domain = domain.lower()
    for brand, info in load_brands().items():
        for legit in info["domains"]:
            if domain == legit or domain.endswith("." + legit):
                return brand
    return None


@dataclass
class LookalikeMatch:
    domain: str
    brand: str
    legit_domain: str
    technique: str  # homoglyph | typosquat | combosquat | subdomain-spoof
    detail: str


def find_lookalike(host: str) -> LookalikeMatch | None:
    """Detect whether ``host`` imitates a protected brand domain without belonging to it."""
    host = host.lower().strip(".")
    if not host or is_ip(host) or brand_for_domain(host):
        return None

    decoded = to_unicode(host)
    reg = registrable_domain(decoded)
    cand_label = _label(decoded)
    cand_skel = skeleton(cand_label)

    for brand, info in load_brands().items():
        for legit in info["domains"]:
            legit_label = _label(legit)
            if len(legit_label) < 4:
                continue  # too short to judge without drowning in false positives

            # paypal.com.secure-login.xyz — brand domain embedded as a subdomain
            if f"{legit}." in decoded and not decoded.endswith(legit):
                return LookalikeMatch(host, brand, legit, "subdomain-spoof",
                                      f"'{legit}' used as a subdomain of '{reg}'")

            if cand_label == legit_label:
                continue  # same label, different TLD: handled as a combosquat below only if extra tokens

            if cand_skel == skeleton(legit_label):
                return LookalikeMatch(host, brand, legit, "homoglyph",
                                      f"'{decoded}' renders like '{legit}'")

            dist = damerau_levenshtein(cand_label, legit_label)
            limit = 1 if len(legit_label) < 8 else 2
            if 0 < dist <= limit:
                return LookalikeMatch(host, brand, legit, "typosquat",
                                      f"'{cand_label}' is {dist} edit(s) from '{legit_label}'")

            tokens = [t for t in cand_label.replace("_", "-").split("-") if t]
            if len(tokens) > 1 and (legit_label in tokens or skeleton(legit_label) in cand_skel):
                return LookalikeMatch(host, brand, legit, "combosquat",
                                      f"brand name '{legit_label}' combined with extra terms in '{reg}'")
    return None
