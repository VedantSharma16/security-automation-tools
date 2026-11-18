"""Domain helpers: registrable-domain extraction and lookalike/typosquat detection.

The lookalike check is deliberately explainable: every match reports *why* it
matched (edit distance, homoglyph substitution, IDN/punycode, or brand
embedded in a longer name) so an analyst can sanity-check it in seconds.
"""

from __future__ import annotations

from dataclasses import dataclass

# Brands commonly impersonated in credential-phishing campaigns, mapped to
# their legitimate registrable domains. Override/extend with --brands.
DEFAULT_PROTECTED_BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com"],
    "office365": ["office.com", "microsoft.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazonaws.com"],
    "netflix": ["netflix.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "linkedin": ["linkedin.com"],
    "facebook": ["facebook.com", "fb.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "okta": ["okta.com"],
}

# Multi-label public suffixes we care about; a full PSL is overkill for triage.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "edu.au",
    "gov.au", "co.nz", "co.in", "co.jp", "com.br", "com.mx", "co.za", "com.sg",
}

# Words phishers glue onto a brand ("paypalsecure", "appleidverify"). Requiring
# one avoids flagging innocent names that merely start with a brand ("applesauce").
_LURE_WORDS = (
    "secure", "security", "login", "logon", "signin", "verify", "verification", "account", "support",
    "update", "service", "help", "auth", "billing", "alert", "id", "online", "portal", "web", "mail",
)

# ASCII look-alike substitutions used in typosquats, applied to normalize a label.
_ASCII_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a")]

# Common Unicode confusables (Cyrillic/Greek) -> Latin.
_UNICODE_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "ν": "v", "ο": "o", "α": "a",
    "ӏ": "l", "ʟ": "l", "ᴠ": "v",
})


def registrable_domain(host: str) -> str:
    host = host.lower().strip().strip(".")
    if host.startswith("[") or host.replace(".", "").isdigit():
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _decode_idn(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna") if "xn--" in domain else domain
    except UnicodeError:
        return domain


def _damerau_levenshtein(a: str, b: str) -> int:
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


@dataclass
class LookalikeMatch:
    domain: str
    brand: str
    technique: str
    detail: str

    def to_dict(self) -> dict:
        return {"domain": self.domain, "brand": self.brand, "technique": self.technique, "detail": self.detail}


def find_lookalike(domain: str, brands: dict[str, list[str]] | None = None) -> LookalikeMatch | None:
    """Return a match if ``domain`` impersonates a protected brand, else None."""
    brands = brands or DEFAULT_PROTECTED_BRANDS
    reg = registrable_domain(domain)
    legit = {d for ds in brands.values() for d in ds}
    if reg in legit:
        return None

    decoded = _decode_idn(reg)
    label = decoded.split(".")[0]
    is_idn = decoded != reg
    confusable_norm = label.translate(_UNICODE_CONFUSABLES)
    ascii_norm = confusable_norm
    for src, dst in _ASCII_HOMOGLYPHS:
        ascii_norm = ascii_norm.replace(src, dst)
    compact = ascii_norm.replace("-", "")

    for brand in brands:
        if is_idn and confusable_norm == brand:
            return LookalikeMatch(reg, brand, "idn_homograph", f"punycode {reg} renders as '{decoded}'")
        if ascii_norm == brand and label != brand:
            return LookalikeMatch(reg, brand, "homoglyph", f"'{label}' normalizes to '{brand}'")
        if label == brand:
            # Exact brand label on a non-official TLD, e.g. paypal.co / microsoft.support
            return LookalikeMatch(reg, brand, "tld_swap", f"brand name on unofficial domain {reg}")
        if len(brand) >= 5 and 0 < _damerau_levenshtein(compact, brand) <= (1 if len(brand) < 8 else 2):
            return LookalikeMatch(
                reg, brand, "typosquat", f"'{label}' is edit distance "
                f"{_damerau_levenshtein(compact, brand)} from '{brand}'"
            )
        tokens = ascii_norm.split("-")
        glued_lure = compact.startswith(brand) and compact[len(brand):].startswith(_LURE_WORDS)
        if len(brand) >= 4 and compact != brand and (brand in tokens or glued_lure):
            note = f" (normalized: '{ascii_norm}')" if ascii_norm != label else ""
            return LookalikeMatch(reg, brand, "brand_embedding", f"'{brand}' embedded in '{label}'{note}")
    return None
