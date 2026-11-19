"""Domain intelligence: registrable-domain extraction and lookalike detection.

Lookalike (typosquat / homoglyph) detection combines three signals against a
list of protected domains (well-known brands plus any the analyst supplies,
e.g. their own organisation's domain):

1. Homoglyph skeleton: IDNA-decode, map confusable characters (Cyrillic 'а',
   digit '0', 'rn' -> 'm', ...) to a canonical form, and compare.
2. Edit distance: Damerau-Levenshtein distance <= 2 on the leftmost label of
   the registrable domain ("paypa1", "micros0ft", "gooogle").
3. Brand embedding: the brand label appears inside a different registrable
   domain ("paypal-account-verify.com", "microsoft.login-secure.xyz").
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

# Second-level public suffixes common enough to matter for registrable-domain
# extraction. A full Public Suffix List is deliberately not vendored to keep the
# tool dependency-free; this covers the cases seen in practice in phishing.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.in", "co.jp", "com.br", "com.mx", "com.cn", "com.sg", "co.za",
}

# Visually confusable characters -> canonical Latin. Applied after IDNA decode.
CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s", "|": "l", "i": "l",
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "l",
    "ј": "j", "ԁ": "d", "ѕ": "s", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t", "в": "b",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "l", "κ": "k", "υ": "u",
}
MULTI_CHAR_CONFUSABLES = [("rn", "m"), ("vv", "w"), ("cl", "d")]


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]
    keywords: tuple[str, ...]


@dataclass(frozen=True)
class Lookalike:
    domain: str
    imitates: str
    brand: str
    technique: str  # "homoglyph", "typosquat", "brand-in-domain", "punycode"
    detail: str


@lru_cache(maxsize=1)
def load_intel() -> dict:
    with resources.files("phishscope.data").joinpath("brands.json").open(encoding="utf-8") as fh:
        return json.load(fh)


def brands() -> list[Brand]:
    return [
        Brand(b["brand"], tuple(b["domains"]), tuple(b["keywords"]))
        for b in load_intel()["brands"]
    ]


def decode_idna(host: str) -> str:
    """Decode any punycode (xn--) labels to Unicode; leave the rest untouched."""
    labels = []
    for label in host.lower().strip(".").split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1: 'a.b.example.co.uk' -> 'example.co.uk'."""
    host = host.lower().strip(".").split(":")[0]
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _label(domain: str) -> str:
    """The brand-bearing label of a registrable domain: 'paypal.co.uk' -> 'paypal'."""
    return registrable_domain(domain).split(".")[0]


def skeleton(text: str) -> str:
    out = "".join(CONFUSABLES.get(ch, ch) for ch in decode_idna(text))
    for seq, repl in MULTI_CHAR_CONFUSABLES:
        out = out.replace(seq, repl)
    return out


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (insert, delete, substitute, transpose)."""
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


def protected_domains(extra: list[str] | None = None) -> list[tuple[str, str]]:
    """(domain, brand) pairs to defend: built-in brands + analyst-supplied domains."""
    pairs = [(d, b.name) for b in brands() for d in b.domains]
    for d in extra or []:
        pairs.append((d.lower(), f"{d.lower()} (protected)"))
    return pairs


def is_legitimate(host: str, extra: list[str] | None = None) -> bool:
    """True if host is, or is a subdomain of, a protected domain."""
    reg = registrable_domain(host)
    return any(reg == d for d, _ in protected_domains(extra))


def find_lookalike(host: str, extra: list[str] | None = None) -> Lookalike | None:
    """Return the strongest lookalike match for `host`, or None if it looks clean."""
    if not host:
        return None
    host = host.lower().strip(".")
    if is_legitimate(host, extra):
        return None

    reg = registrable_domain(host)
    reg_label = _label(reg)
    reg_skel = skeleton(reg_label)
    host_decoded = decode_idna(host)

    for target, brand in protected_domains(extra):
        t_label = _label(target)
        if len(t_label) < 4:
            # Short labels like "dhl" produce too many edit-distance false positives;
            # they are still caught by the brand-in-domain check below.
            pass
        elif reg_label != t_label and reg_skel == skeleton(t_label):
            technique = "punycode" if "xn--" in reg else "homoglyph"
            return Lookalike(
                host, target, brand, technique,
                f"'{decode_idna(reg)}' renders like '{target}'",
            )
        elif len(t_label) >= 5 and 0 < damerau_levenshtein(reg_label, t_label) <= 2:
            return Lookalike(
                host, target, brand, "typosquat",
                f"'{reg_label}' is {damerau_levenshtein(reg_label, t_label)} edit(s) from '{t_label}'",
            )

    host_skel = skeleton(host_decoded)
    tokens = set(host_decoded.replace("-", ".").split("."))
    skel_tokens = set(host_skel.replace("-", ".").split("."))
    for b in brands():
        for kw in b.keywords:
            kw_skel = skeleton(kw)
            # Exact token match ("dhl-tracking.com") or, for long keywords, a
            # substring match ("paypalsecure.net"). Short substrings are skipped
            # to avoid "apple" firing on "pineapple". The same test is repeated on
            # the homoglyph skeleton to catch "micros0ft-support.com".
            if kw in tokens or (len(kw) >= 6 and kw in host_decoded):
                technique = "brand-in-domain"
            elif kw_skel in skel_tokens or (len(kw) >= 6 and kw_skel in host_skel):
                technique = "homoglyph-brand-in-domain"
            else:
                continue
            return Lookalike(
                host, b.domains[0], b.name, technique,
                f"brand '{kw}' imitated in unrelated domain '{decode_idna(reg)}'",
            )
    return None
