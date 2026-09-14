"""TLS protocol version and certificate expiry checks."""

from __future__ import annotations

from http_audit.fetcher import HttpResponse
from http_audit.report import Finding

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def check_tls(response: HttpResponse) -> list[Finding]:
    if not response.url.startswith("https://"):
        return [
            Finding(
                "tls",
                "Transport encryption",
                "critical",
                "Target was audited over plain HTTP; traffic is unencrypted.",
                "Serve the site exclusively over HTTPS and redirect HTTP to HTTPS.",
            )
        ]

    tls_info = response.tls
    if tls_info is None:
        return [
            Finding(
                "tls",
                "TLS certificate",
                "info",
                "TLS handshake details were not collected for this scan.",
            )
        ]

    findings: list[Finding] = []

    if tls_info.protocol_version in _WEAK_PROTOCOLS:
        findings.append(
            Finding(
                "tls",
                "TLS protocol version",
                "high",
                f"Server negotiated {tls_info.protocol_version}, a deprecated/weak protocol version.",
                "Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1; require TLS 1.2 or higher.",
            )
        )
    else:
        findings.append(
            Finding("tls", "TLS protocol version", "pass", f"Server negotiated {tls_info.protocol_version}.")
        )

    if tls_info.days_until_expiry is not None:
        if tls_info.days_until_expiry < 0:
            findings.append(
                Finding(
                    "tls",
                    "Certificate expiry",
                    "critical",
                    f"TLS certificate expired {abs(tls_info.days_until_expiry)} day(s) ago "
                    f"(issuer: {tls_info.issuer}).",
                    "Renew the certificate immediately.",
                )
            )
        elif tls_info.days_until_expiry < 30:
            findings.append(
                Finding(
                    "tls",
                    "Certificate expiry",
                    "medium",
                    f"TLS certificate expires in {tls_info.days_until_expiry} day(s) (issuer: {tls_info.issuer}).",
                    "Renew the certificate before it expires; automate renewal if not already.",
                )
            )
        else:
            findings.append(
                Finding(
                    "tls",
                    "Certificate expiry",
                    "pass",
                    f"Certificate valid for {tls_info.days_until_expiry} more day(s) (issuer: {tls_info.issuer}).",
                )
            )

    return findings
