"""robots.txt and sitemap.xml parsing.

Sitemap URLs are extracted with a regex rather than an XML parser. A
sitemap is content served by (or spoofable on) the target being scanned,
i.e. attacker-influenced input — even stdlib `xml.etree.ElementTree` is a
known XXE / billion-laughs vector unless the parser is explicitly hardened.
A regex extractor sidesteps that whole vulnerability class; we don't need
XML well-formedness validation for what we use this for (collecting `<loc>`
URLs to look at).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SENSITIVE_KEYWORDS = (
    "admin",
    "backup",
    "config",
    "secret",
    "private",
    "internal",
    ".git",
    ".env",
    "database",
    "db",
    "debug",
    "staging",
    "upload",
    "tmp",
    "old",
    "wp-admin",
    "phpmyadmin",
    "swagger",
    "actuator",
)


@dataclass(frozen=True)
class RobotsFindings:
    disallowed_paths: tuple
    sitemaps: tuple
    sensitive_paths: tuple


def parse_robots_txt(text: str) -> RobotsFindings:
    disallowed = []
    sitemaps = []

    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "disallow" and value:
            disallowed.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)

    sensitive = tuple(path for path in disallowed if any(kw in path.lower() for kw in SENSITIVE_KEYWORDS))

    return RobotsFindings(disallowed_paths=tuple(disallowed), sitemaps=tuple(sitemaps), sensitive_paths=sensitive)


_LOC_PATTERN = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def parse_sitemap_xml(text: str) -> list:
    return _LOC_PATTERN.findall(text or "")
