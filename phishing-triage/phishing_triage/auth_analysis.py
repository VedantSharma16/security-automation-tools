"""Parse RFC 8601 `Authentication-Results` headers for SPF/DKIM/DMARC verdicts.

A receiving mail server (Gmail, Outlook, a corporate gateway, ...) stamps this
header with the result of its own SPF/DKIM/DMARC checks *before* an analyst ever
sees the message. We don't re-implement those checks (that requires DNS lookups
against records that may no longer exist by the time the email is triaged) --
instead we read the verdict the receiving server already reached, which is the
same signal a real inbox's "this might be spam" banner is built on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", re.IGNORECASE)
_KNOWN_RESULTS = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
    "bestguesspass",
    "policy",
}


@dataclass(frozen=True)
class AuthResult:
    header_present: bool
    spf: str | None
    dkim: str | None
    dmarc: str | None

    @property
    def fully_authenticated(self) -> bool:
        return self.spf == "pass" and self.dkim == "pass" and self.dmarc == "pass"

    @property
    def any_hard_fail(self) -> bool:
        return self.spf == "fail" or self.dmarc == "fail"

    def as_dict(self) -> dict:
        return {
            "header_present": self.header_present,
            "spf": self.spf,
            "dkim": self.dkim,
            "dmarc": self.dmarc,
            "fully_authenticated": self.fully_authenticated,
        }


def analyze_authentication(auth_headers: tuple[str, ...] | list[str]) -> AuthResult:
    """Extract spf/dkim/dmarc verdicts, preferring the topmost (most recent hop) header."""
    if not auth_headers:
        return AuthResult(header_present=False, spf=None, dkim=None, dmarc=None)

    results: dict[str, str] = {}
    for header in auth_headers:
        for mechanism, value in _RESULT_RE.findall(header):
            mechanism = mechanism.lower()
            value = value.lower()
            if mechanism in results or value not in _KNOWN_RESULTS:
                continue
            results[mechanism] = value

    return AuthResult(
        header_present=True,
        spf=results.get("spf"),
        dkim=results.get("dkim"),
        dmarc=results.get("dmarc"),
    )
