"""TLS handshake / certificate checks."""

from __future__ import annotations

from ..models import Finding, TLSInfo

_DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def check_tls(tls: TLSInfo | None) -> list[Finding]:
    if tls is None:
        return []

    if tls.error:
        return [
            Finding(
                id="tls-handshake-failed",
                title="TLS handshake failed",
                severity="high",
                category="tls",
                description=(
                    "Could not complete a TLS handshake or validate the "
                    "certificate chain against the host's trust store."
                ),
                remediation=(
                    "Investigate certificate validity, chain completeness, and "
                    "hostname match; this may also indicate a self-signed or "
                    "expired certificate."
                ),
                evidence=tls.error,
            )
        ]

    findings: list[Finding] = []

    if tls.protocol_version in _DEPRECATED_PROTOCOLS:
        findings.append(
            Finding(
                id="tls-deprecated-protocol",
                title=f"Deprecated TLS protocol negotiated ({tls.protocol_version})",
                severity="critical" if tls.protocol_version in {"SSLv2", "SSLv3"} else "high",
                category="tls",
                description=(
                    f"The server negotiated {tls.protocol_version}, which has "
                    "known cryptographic weaknesses and is disabled by modern "
                    "browsers and clients."
                ),
                remediation="Disable protocols older than TLS 1.2; prefer TLS 1.3.",
                evidence=tls.protocol_version or "",
            )
        )

    if tls.days_until_expiry is not None:
        findings.extend(_check_expiry(tls))

    if tls.issuer is not None and tls.issuer == tls.subject:
        findings.append(
            Finding(
                id="tls-self-signed",
                title="Certificate appears self-signed",
                severity="medium",
                category="tls",
                description="The certificate's issuer and subject are identical, suggesting it is self-signed.",
                remediation="Use a certificate issued by a trusted public CA (or internal CA trusted by clients) for anything beyond local testing.",
                evidence=f"subject={tls.subject}",
            )
        )

    return findings


def _check_expiry(tls: TLSInfo) -> list[Finding]:
    days = tls.days_until_expiry
    assert days is not None

    if days < 0:
        return [
            Finding(
                id="tls-cert-expired",
                title="TLS certificate has expired",
                severity="critical",
                category="tls",
                description=f"The certificate expired {abs(days)} day(s) ago ({tls.not_after}).",
                remediation="Renew the certificate immediately.",
                evidence=tls.not_after or "",
            )
        ]
    if days < 14:
        return [
            Finding(
                id="tls-cert-expiring-soon",
                title="TLS certificate expires within 14 days",
                severity="high",
                category="tls",
                description=f"The certificate expires in {days} day(s) ({tls.not_after}).",
                remediation="Renew the certificate before it expires to avoid an outage.",
                evidence=tls.not_after or "",
            )
        ]
    if days < 30:
        return [
            Finding(
                id="tls-cert-expiring-within-month",
                title="TLS certificate expires within 30 days",
                severity="medium",
                category="tls",
                description=f"The certificate expires in {days} day(s) ({tls.not_after}).",
                remediation="Schedule certificate renewal.",
                evidence=tls.not_after or "",
            )
        ]
    return []
