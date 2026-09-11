"""TLS protocol version and certificate expiry checks."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .models import CheckResult

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_EXPIRY_CRITICAL_DAYS = 0
_EXPIRY_HIGH_DAYS = 14
_EXPIRY_MEDIUM_DAYS = 30


def analyze_tls(
    protocol: Optional[str],
    not_after: Optional[datetime],
    error: Optional[str],
) -> list[CheckResult]:
    if error:
        return [CheckResult(
            "tls-handshake", "tls", "fail", "high", "TLS handshake",
            f"Could not complete a TLS handshake: {error}",
            "Ensure a valid, complete certificate chain is served and that the endpoint "
            "supports a modern TLS version.",
        )]

    results = []

    if protocol in _WEAK_PROTOCOLS:
        results.append(CheckResult(
            "tls-protocol", "tls", "fail", "high", "TLS protocol version",
            f"Negotiated {protocol}, which is deprecated.",
            "Disable SSLv3/TLS 1.0/1.1; require TLS 1.2 or newer.",
        ))
    elif protocol:
        results.append(CheckResult("tls-protocol", "tls", "pass", "info",
                                    "TLS protocol version", f"Negotiated {protocol}.", None))

    if not_after:
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < _EXPIRY_CRITICAL_DAYS:
            results.append(CheckResult(
                "tls-expiry", "tls", "fail", "critical", "Certificate expiry",
                f"Certificate expired {abs(days_left)} day(s) ago.",
                "Renew the certificate immediately.",
            ))
        elif days_left <= _EXPIRY_HIGH_DAYS:
            results.append(CheckResult(
                "tls-expiry", "tls", "fail", "high", "Certificate expiry",
                f"Certificate expires in {days_left} day(s).",
                "Renew the certificate before it expires.",
            ))
        elif days_left <= _EXPIRY_MEDIUM_DAYS:
            results.append(CheckResult(
                "tls-expiry", "tls", "warn", "medium", "Certificate expiry",
                f"Certificate expires in {days_left} day(s).",
                "Schedule certificate renewal.",
            ))
        else:
            results.append(CheckResult(
                "tls-expiry", "tls", "pass", "info", "Certificate expiry",
                f"Valid for {days_left} more day(s).", None,
            ))

    return results
