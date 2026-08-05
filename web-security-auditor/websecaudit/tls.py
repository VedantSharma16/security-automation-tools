"""TLS configuration checks, given a fetcher.TLSInfo probe result."""

from __future__ import annotations

from .fetcher import TLSInfo
from .findings import Finding

_DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def analyze_tls(tls: TLSInfo | None) -> list[Finding]:
    if tls is None:
        return []

    if tls.error:
        return [
            Finding(
                id="tls-probe-failed",
                severity="medium",
                category="tls",
                message=f"Direct TLS handshake probe failed: {tls.error}",
                recommendation="Verify the certificate chain and supported protocol versions manually.",
            )
        ]

    findings = []

    if tls.protocol_version in _DEPRECATED_PROTOCOLS:
        findings.append(
            Finding(
                id="deprecated-tls-protocol",
                severity="critical",
                category="tls",
                message=f"Server negotiated deprecated protocol {tls.protocol_version}.",
                recommendation="Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1; require TLS 1.2 or higher.",
            )
        )

    if tls.days_until_expiry is not None:
        if tls.days_until_expiry < 0:
            findings.append(
                Finding(
                    id="tls-certificate-expired",
                    severity="critical",
                    category="tls",
                    message=f"TLS certificate expired {abs(tls.days_until_expiry)} day(s) ago.",
                    recommendation="Renew the TLS certificate immediately.",
                )
            )
        elif tls.days_until_expiry < 14:
            findings.append(
                Finding(
                    id="tls-certificate-expiring-soon",
                    severity="high",
                    category="tls",
                    message=f"TLS certificate expires in {tls.days_until_expiry} day(s).",
                    recommendation="Renew the TLS certificate now to avoid an outage.",
                )
            )
        elif tls.days_until_expiry < 30:
            findings.append(
                Finding(
                    id="tls-certificate-expiring-soon",
                    severity="medium",
                    category="tls",
                    message=f"TLS certificate expires in {tls.days_until_expiry} day(s).",
                    recommendation="Schedule certificate renewal within the next few weeks.",
                )
            )

    return findings
