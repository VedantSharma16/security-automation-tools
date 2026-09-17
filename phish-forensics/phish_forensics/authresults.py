"""Parse RFC 8601 `Authentication-Results` headers into SPF/DKIM/DMARC
verdicts. When a message hops through multiple mail servers there can be
several such headers; the topmost one is added last, by the final receiving
server, so it is the most trustworthy for the recipient and takes priority
for any mechanism it reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_MECHANISM_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)")

PASS_LIKE = {"pass"}
FAIL_LIKE = {"fail", "softfail", "permerror"}
WEAK_LIKE = {"neutral", "none", "temperror", "policy"}


@dataclass
class AuthResultsSummary:
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    raw_headers: list[str] | None = None

    @property
    def evaluated(self) -> bool:
        return bool(self.raw_headers)

    def verdict_for(self, mechanism: str) -> str | None:
        return getattr(self, mechanism, None)

    def failing_mechanisms(self) -> list[str]:
        return [
            m for m in ("spf", "dkim", "dmarc")
            if (v := self.verdict_for(m)) is not None and v.lower() in FAIL_LIKE
        ]

    def fully_authenticated(self) -> bool:
        """True only when all three mechanisms were evaluated and passed."""
        return all(self.verdict_for(m) is not None and self.verdict_for(m).lower() in PASS_LIKE for m in ("spf", "dkim", "dmarc"))


def parse_authentication_results(headers: list[str]) -> AuthResultsSummary:
    summary = AuthResultsSummary(raw_headers=list(headers))
    for header in headers:
        for mechanism, result in _MECHANISM_RE.findall(header):
            mechanism = mechanism.lower()
            if getattr(summary, mechanism) is None:
                setattr(summary, mechanism, result.lower())
    return summary
