"""Domain utilities: registrable-domain extraction and lookalike detection.

Lookalike detection combines three signals, each mapping to a real phishing
technique:

* **Homoglyph skeletons** - ``paypa1.com`` / ``rnicrosoft.com`` collapse to the
  same skeleton as the protected brand once visually confusable characters
  are normalised (``1->l``, ``rn->m``, ``0->o``, ``vv->w`` ...).
* **IDN / punycode** - ``xn--pypal-4ve.com`` is decoded and its Unicode
  characters folded to ASCII look-alikes before comparison.
* **Edit distance** - typosquats such as ``micros0ft.com`` or ``amazom.com``
  within a small Damerau-Levenshtein distance of a protected label.

Plus **brand-in-subdomain / combosquatting** (``paypal.com.secure-login.top``,
``paypal-verify.com``), which edit distance alone misses.
"""

from __future__ import annotations

import ipaddress
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

# A small built-in list of multi-label public suffixes. A full Public Suffix
# List would be more precise; this keeps the tool dependency-free and covers
# the suffixes seen most often in phishing infrastructure.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.in", "co.jp", "com.br", "com.cn", "com.mx", "co.za",
    "com.sg", "com.tr", "com.ar", "co.kr",
}

# Single characters that are visually confusable with an ASCII letter.
_CHAR_CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "i": "l", "|": "l",
    # Common Cyrillic / Greek homoglyphs (NFKD does not fold these).
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "l", "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n", "ѕ": "s", "ԛ": "q",
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "κ": "k",
}
# Multi-character sequences that render like a single letter.
_SEQ_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))


def hostname(url: str) -> str:
    """Return the lowercase hostname for a URL (tolerates scheme-less ``www.`` links)."""
    if url.startswith("//"):
        url = "http:" + url
    elif "://" not in url:
        url = "http://" + url
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    """``mail.login.example.co.uk`` -> ``example.co.uk`` (best effort, no PSL)."""
    host = host.lower().rstrip(".")
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def decode_idn(host: str) -> str:
    """Decode any punycode (``xn--``) labels to Unicode; leave others untouched."""
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
                continue
            except UnicodeError:
                pass
        out.append(label)
    return ".".join(out)


def skeleton(label: str) -> str:
    """Collapse visually confusable characters so lookalikes compare equal."""
    s = unicodedata.normalize("NFKD", label.lower())
    s = "".join(_CHAR_CONFUSABLES.get(c, c) for c in s if not unicodedata.combining(c))
    for seq, rep in _SEQ_CONFUSABLES:
        s = s.replace(seq, rep)
    return s.replace("-", "")


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (handles adjacent transpositions)."""
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


def _sld(domain: str) -> str:
    """Second-level label: ``paypal.com`` -> ``paypal``, ``bbc.co.uk`` -> ``bbc``."""
    return domain.split(".")[0]


@dataclass
class LookalikeMatch:
    domain: str
    impersonates: str
    technique: str   # homoglyph | idn_homograph | typosquat | combosquat | brand_in_subdomain
    detail: str


def find_lookalike(host: str, protected: list[str]) -> LookalikeMatch | None:
    """Return a match if ``host`` imitates (but is not) one of the protected domains."""
    host = host.lower().rstrip(".")
    if not host or is_ip(host):
        return None
    reg = registrable_domain(host)
    protected_set = {p.lower() for p in protected}
    if reg in protected_set:
        return None  # legitimately owned (including subdomains)

    decoded = decode_idn(reg)
    is_idn = decoded != reg
    label = _sld(decoded)
    label_skel = skeleton(label)

    for p in protected_set:
        p_label = _sld(p)
        if len(p_label) < 4:
            continue  # too short to compare meaningfully (ups, dhl...): too many FPs
        p_skel = skeleton(p_label)

        if label_skel == p_skel and label != p_label:
            technique = "idn_homograph" if is_idn else "homoglyph"
            return LookalikeMatch(reg, p, technique, f"'{decoded}' renders like '{p}'")

        if label == p_label and reg != p:
            # Same brand label, different TLD: paypal.co, microsoft.support
            return LookalikeMatch(reg, p, "typosquat", f"brand label on foreign TLD ('{reg}')")

        if len(p_label) >= 5:
            dist = damerau_levenshtein(label_skel, p_skel)
            if 0 < dist <= (1 if len(p_label) < 8 else 2):
                return LookalikeMatch(reg, p, "typosquat", f"edit distance {dist} from '{p}'")

        tokens = [skeleton(t) for t in label.replace("_", "-").split("-") if t]
        if p_skel in tokens and len(tokens) > 1:
            return LookalikeMatch(reg, p, "combosquat", f"brand '{p_label}' combined with other words")

    # Brand used as a subdomain of an unrelated domain: paypal.com.verify-acct.top
    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    if sub:
        sub_labels = set(sub.split("."))
        for p in protected_set:
            if p in sub or _sld(p) in sub_labels and len(_sld(p)) >= 5:
                return LookalikeMatch(reg, p, "brand_in_subdomain", f"'{p}' placed in subdomain of '{reg}'")
    return None
