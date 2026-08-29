"""DNS record enumeration and basic email-security posture checks.

Looks up the common record types an external recon pass cares about, and
separately checks for SPF/DMARC TXT records -- their absence is one of the
most common, easy-to-spot email-spoofing weaknesses on real domains.
"""

from __future__ import annotations

import dns.resolver

from .findings import Finding, Severity

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


def _make_resolver(timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _query(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> list[str]:
    try:
        answer = resolver.resolve(name, rdtype)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []
    return [str(rdata).strip('"') for rdata in answer]


def resolve_records(
    domain: str, timeout: float = 5.0, resolver: dns.resolver.Resolver | None = None
) -> dict[str, list[str]]:
    """Resolve the common record types for `domain`. Missing types map to []."""
    resolver = resolver or _make_resolver(timeout)
    return {rdtype: _query(resolver, domain, rdtype) for rdtype in RECORD_TYPES}


def check_email_security(
    domain: str, records: dict[str, list[str]], resolver: dns.resolver.Resolver | None = None
) -> list[Finding]:
    """Check for SPF (in the domain's own TXT records) and DMARC (at _dmarc.<domain>)."""
    findings: list[Finding] = []

    txt_records = records.get("TXT", [])
    has_spf = any(t.lower().startswith("v=spf1") for t in txt_records)
    if not has_spf:
        findings.append(
            Finding(
                source="dns",
                severity=Severity.MEDIUM,
                title="No SPF record",
                detail=(
                    f"{domain} has no SPF (v=spf1) TXT record, making it easier for "
                    "attackers to spoof mail claiming to be from this domain."
                ),
            )
        )

    resolver = resolver or _make_resolver(5.0)
    dmarc_records = _query(resolver, f"_dmarc.{domain}", "TXT")
    has_dmarc = any(t.lower().startswith("v=dmarc1") for t in dmarc_records)
    if not has_dmarc:
        findings.append(
            Finding(
                source="dns",
                severity=Severity.MEDIUM,
                title="No DMARC record",
                detail=(
                    f"_dmarc.{domain} has no DMARC (v=DMARC1) TXT record, so spoofed "
                    "mail for this domain is not policed by receiving mail servers."
                ),
            )
        )

    return findings


def build_findings(
    domain: str, records: dict[str, list[str]], resolver: dns.resolver.Resolver | None = None
) -> list[Finding]:
    findings = [
        Finding(
            source="dns",
            severity=Severity.INFO,
            title=f"{rdtype} records resolved",
            detail=", ".join(values),
        )
        for rdtype, values in records.items()
        if values
    ]
    findings.extend(check_email_security(domain, records, resolver=resolver))
    return findings
