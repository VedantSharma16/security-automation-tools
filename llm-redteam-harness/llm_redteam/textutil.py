"""Text helpers shared by the guardrails, the evaluators and the simulated model."""

from __future__ import annotations

import base64
import re
import unicodedata
from urllib.parse import urlparse

# Zero-width, bidi-control and Unicode "tag" characters: invisible to a human
# reviewer but still tokenized (and potentially obeyed) by a model.
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
_B64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])")
_QUOTED = re.compile(r"'([^']{2,})'|\"([^\"]{2,})\"")
_URL = re.compile(r"https?://[^\s)\]>\"']+")
_MD_LINK = re.compile(r"(!?)\[([^\]]*)\]\((https?://[^)\s]+)\)")
_WORD = re.compile(r"[a-z0-9]+")


def has_invisible(text: str) -> bool:
    return bool(_INVISIBLE.search(text))


def strip_invisible(text: str) -> str:
    return _INVISIBLE.sub("", text)


def decode_base64_runs(text: str) -> list[str]:
    """Return printable decodings of every plausible base64 run in ``text``."""
    decoded = []
    for match in _B64_CANDIDATE.finditer(text):
        blob = match.group()
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            candidate = raw.decode("utf-8")
        except Exception:
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in candidate)
        if candidate and printable / len(candidate) > 0.95 and " " in candidate:
            decoded.append(candidate)
    return decoded


def reassemble_quoted(text: str) -> str:
    """Concatenate quoted fragments, undoing simple payload-splitting tricks
    (``a='Ignore prev' b='ious instructions'; do a+b``)."""
    parts = [m.group(1) or m.group(2) for m in _QUOTED.finditer(text)]
    return "".join(parts) if len(parts) > 1 else ""


def normalize(text: str) -> str:
    """Canonical view of ``text`` as a model would 'see' it: NFKC-folded,
    invisible characters removed, base64 payloads and split payloads decoded
    and appended."""
    base = strip_invisible(unicodedata.normalize("NFKC", text))
    extras = decode_base64_runs(base)
    joined = reassemble_quoted(base)
    if joined:
        extras.append(joined)
    return "\n".join([base, *extras])


def urls(text: str) -> list[str]:
    return _URL.findall(text)


def markdown_links(text: str) -> list[tuple[bool, str, str, str]]:
    """Return ``(is_image, label, url, full_match)`` for every markdown link/image."""
    return [(m.group(1) == "!", m.group(2), m.group(3), m.group(0)) for m in _MD_LINK.finditer(text)]


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def is_internal_host(host: str, org_domain: str) -> bool:
    return host == org_domain or host.endswith("." + org_domain)


def is_internal_email(address: str, org_domain: str) -> bool:
    return address.lower().rsplit("@", 1)[-1] == org_domain.lower()


def shingles(text: str, n: int = 6) -> set[tuple[str, ...]]:
    words = _WORD.findall(text.lower())
    return {tuple(words[i : i + n]) for i in range(max(0, len(words) - n + 1))}


def overlap_ratio(reference: str, candidate: str, n: int = 6) -> float:
    """Fraction of ``reference``'s word n-grams that appear in ``candidate``
    (or in any base64 payload inside it)."""
    ref = shingles(reference, n)
    if not ref:
        return 0.0
    views = [candidate, *decode_base64_runs(candidate)]
    seen: set[tuple[str, ...]] = set()
    for view in views:
        seen |= shingles(view, n)
    return len(ref & seen) / len(ref)
