"""Parse the `Authentication-Results` header into SPF/DKIM/DMARC verdicts.

Mail gateways (Gmail, Outlook, etc.) stamp this header with the results of
their own SPF/DKIM/DMARC checks before delivering a message. This module
never re-implements those checks -- it only reads what the receiving
gateway already verified, which is the same trust boundary a human analyst
uses when triaging a reported email.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_MECHANISM_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", re.IGNORECASE)

_FAILING_VERDICTS = {"fail", "softfail", "permerror"}


@dataclass
class AuthResult:
    spf: str | None
    dkim: str | None
    dmarc: str | None

    @property
    def present(self) -> bool:
        return self.spf is not None or self.dkim is not None or self.dmarc is not None

    @property
    def failing_mechanisms(self) -> list[str]:
        return [
            name
            for name, verdict in (("spf", self.spf), ("dkim", self.dkim), ("dmarc", self.dmarc))
            if verdict in _FAILING_VERDICTS
        ]

    @property
    def dmarc_fail(self) -> bool:
        return self.dmarc == "fail"


def parse_authentication_results(raw: str | None) -> AuthResult:
    """Extract the first spf=/dkim=/dmarc= verdict from a raw header value."""
    if not raw:
        return AuthResult(spf=None, dkim=None, dmarc=None)

    verdicts: dict[str, str] = {}
    for mechanism, verdict in _MECHANISM_RE.findall(raw):
        verdicts.setdefault(mechanism.lower(), verdict.lower())

    return AuthResult(spf=verdicts.get("spf"), dkim=verdicts.get("dkim"), dmarc=verdicts.get("dmarc"))
