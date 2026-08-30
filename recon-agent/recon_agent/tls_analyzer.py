"""Rule-based analysis of a TLS handshake probe. Pure functions, no I/O."""

from __future__ import annotations

from .models import Finding, TLSResult

_WEAK_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_EXPIRY_HIGH_DAYS = 7
_EXPIRY_MEDIUM_DAYS = 30


def analyze_tls(tls: TLSResult) -> list[Finding]:
    if not tls.ok:
        return []

    findings: list[Finding] = []
    source_url = f"https://{tls.host}:{tls.port}"

    if tls.version in _WEAK_VERSIONS:
        findings.append(
            Finding(
                id="tls-weak-protocol-version",
                title=f"Weak TLS protocol version negotiated ({tls.version})",
                severity="high",
                category="transport-security",
                evidence=f"Negotiated protocol: {tls.version}",
                recommendation="Disable TLS 1.1 and below server-side; require TLS 1.2 or newer.",
                source_url=source_url,
            )
        )

    if tls.days_until_expiry is not None:
        if tls.days_until_expiry < 0:
            findings.append(
                Finding(
                    id="tls-certificate-expired",
                    title="TLS certificate has expired",
                    severity="critical",
                    category="transport-security",
                    evidence=f"Certificate expired {-tls.days_until_expiry} day(s) ago (notAfter={tls.not_after})",
                    recommendation="Renew the certificate immediately — expired certs break trust for every client.",
                    source_url=source_url,
                )
            )
        elif tls.days_until_expiry <= _EXPIRY_HIGH_DAYS:
            findings.append(
                Finding(
                    id="tls-certificate-expiring-soon",
                    title="TLS certificate expires within a week",
                    severity="high",
                    category="transport-security",
                    evidence=f"{tls.days_until_expiry} day(s) until expiry (notAfter={tls.not_after})",
                    recommendation="Renew now, or confirm automated renewal (e.g. ACME/Let's Encrypt) is actually running.",
                    source_url=source_url,
                )
            )
        elif tls.days_until_expiry <= _EXPIRY_MEDIUM_DAYS:
            findings.append(
                Finding(
                    id="tls-certificate-expiring-soon",
                    title="TLS certificate expires within 30 days",
                    severity="medium",
                    category="transport-security",
                    evidence=f"{tls.days_until_expiry} day(s) until expiry (notAfter={tls.not_after})",
                    recommendation="Schedule renewal and confirm automated renewal is configured.",
                    source_url=source_url,
                )
            )

    return findings
