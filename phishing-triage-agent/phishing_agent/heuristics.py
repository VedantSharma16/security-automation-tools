"""Standalone detection heuristics used by the agent's investigation tools.

Kept dependency-free and separate from `tools.py` so each heuristic can be
unit-tested in isolation from the email-parsing/tool-dispatch layer.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

RISKY_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar",
    ".iso", ".img", ".lnk", ".docm", ".xlsm", ".pptm", ".html", ".htm",
    ".hta", ".wsf", ".msi",
}

URGENCY_PHRASES = [
    "verify your account", "your account has been suspended", "act now",
    "immediate action required", "confirm your password", "click here immediately",
    "your account will be closed", "unusual activity detected", "urgent action required",
    "limited time", "failure to comply", "avoid suspension", "reactivate your account",
    "unauthorized login attempt", "update your payment", "confirm your identity",
]


def levenshtein(a: str, b: str) -> int:
    """Standard O(len(a)*len(b)) edit-distance DP, no dependencies."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def domain_of(url_or_addr: str) -> str:
    """Extract a lowercase registrable-ish domain from a URL or email address."""
    value = url_or_addr.strip().strip("<>")
    if "@" in value and "://" not in value:
        return value.rsplit("@", 1)[-1].lower().strip()
    parsed = urlparse(value)
    host = (parsed.netloc or parsed.path).lower()
    host = host.split("@")[-1]  # strip userinfo@ if present
    host = host.split(":")[0]  # strip port
    return host.strip("/")


def is_ip_literal(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def is_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def closest_trusted_brand(domain: str, trusted_domains: dict[str, str], max_distance: int = 2):
    """Return (brand_domain, brand_name, distance) for the nearest trusted brand
    within `max_distance` edits of either the whole domain or one of its
    hyphen/dot-separated tokens, or None if nothing is close enough.

    Comparing tokens (not just the full domain) catches real-world patterns
    like ``paypa1-secure.com`` — a single-character substitution combined
    with an extra "-secure" word, which would be far too many edits from
    "paypal.com" to catch as a whole-string comparison alone. An exact
    domain match is not a typosquat and returns None.
    """
    if domain in trusted_domains:
        return None

    sld = domain.split(".")[0] if domain else ""
    candidates = {sld} | set(re.split(r"[-_.]", sld))
    candidates.discard("")

    best = None
    for brand_domain, brand_name in trusted_domains.items():
        brand_sld = brand_domain.split(".")[0]
        for candidate in candidates:
            dist = levenshtein(candidate, brand_sld)
            if dist <= max_distance and (best is None or dist < best[2]):
                best = (brand_domain, brand_name, dist)
    return best


def display_name_mismatch(display_name: str, from_addr: str, trusted_domains: dict[str, str]):
    """If the From display name references a known brand but the sending domain
    doesn't belong to that brand, return the brand name being impersonated.
    """
    if not display_name:
        return None
    lowered = display_name.lower()
    sender_domain = domain_of(from_addr)
    for brand_domain, brand_name in trusted_domains.items():
        if brand_name.lower() in lowered and sender_domain != brand_domain:
            return brand_name
    return None


def urgency_language_hits(text: str) -> list[str]:
    lowered = text.lower()
    return [phrase for phrase in URGENCY_PHRASES if phrase in lowered]


def risky_attachment_flags(filename: str) -> list[str]:
    """Return a list of flags (empty if the attachment looks benign)."""
    flags = []
    lower = filename.lower()
    suffixes = [s for s in lower.split(".")[1:]]
    if any(f".{s}" in RISKY_ATTACHMENT_EXTENSIONS for s in suffixes):
        flags.append("risky_extension")
    if len(suffixes) >= 2 and f".{suffixes[-1]}" in RISKY_ATTACHMENT_EXTENSIONS:
        # e.g. invoice.pdf.exe — a benign-looking extension followed by an executable one
        flags.append("double_extension")
    return flags
