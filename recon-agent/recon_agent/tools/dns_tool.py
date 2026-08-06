"""DNS reconnaissance: resolves common record types for a domain and flags
basic email-spoofing and DNS-resiliency issues.

Network access is isolated behind `query_fn` so the analysis logic can be
unit-tested without a resolver or network access.
"""
from __future__ import annotations

from typing import Callable, Dict, List

from ..models import Finding, ToolResult

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

QueryFn = Callable[[str, str], List[str]]


def _default_query(domain: str, rtype: str) -> List[str]:
    import dns.resolver  # imported lazily: only required when actually resolving

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = resolver.resolve(domain, rtype)
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
    ):
        return []
    return [str(r).rstrip(".") for r in answer]


def resolve_records(domain: str, query_fn: QueryFn = _default_query) -> Dict[str, List[str]]:
    records: Dict[str, List[str]] = {}
    for rtype in RECORD_TYPES:
        try:
            records[rtype] = query_fn(domain, rtype)
        except Exception:
            records[rtype] = []
    return records


def run(domain: str, query_fn: QueryFn = _default_query) -> ToolResult:
    records = resolve_records(domain, query_fn)
    try:
        records["DMARC"] = query_fn(f"_dmarc.{domain}", "TXT")
    except Exception:
        records["DMARC"] = []

    findings = analyze_records(domain, records)
    return ToolResult(tool="dns", data=records, findings=findings)


def analyze_records(domain: str, records: Dict[str, List[str]]) -> List[Finding]:
    findings: List[Finding] = []

    if not records.get("A") and not records.get("AAAA"):
        findings.append(
            Finding(
                tool="dns",
                severity="high",
                title="No resolvable A/AAAA records",
                detail=f"{domain} did not resolve to any IPv4 or IPv6 address.",
                recommendation="Confirm the domain is correct and that DNS is configured.",
            )
        )

    txt_records = records.get("TXT", [])
    has_spf = any(t.lower().startswith("v=spf1") for t in txt_records)
    if not has_spf:
        findings.append(
            Finding(
                tool="dns",
                severity="medium",
                title="No SPF record found",
                detail="No TXT record starting with 'v=spf1' was found at the apex domain.",
                recommendation=(
                    "Publish an SPF record to reduce email spoofing risk, or confirm mail "
                    "is not sent from this domain."
                ),
            )
        )

    dmarc_records = records.get("DMARC", [])
    has_dmarc = any("v=dmarc1" in t.lower() for t in dmarc_records)
    if not has_dmarc:
        findings.append(
            Finding(
                tool="dns",
                severity="medium",
                title="No DMARC record found",
                detail=f"No TXT record was found at _dmarc.{domain}.",
                recommendation="Publish a DMARC policy (starting at p=none for monitoring) to detect spoofed mail.",
            )
        )

    ns_records = records.get("NS", [])
    if len(ns_records) == 1:
        findings.append(
            Finding(
                tool="dns",
                severity="low",
                title="Single authoritative nameserver",
                detail=f"Only one NS record was found: {ns_records[0]}.",
                recommendation="Use at least two nameservers, ideally on different networks, for DNS resiliency.",
            )
        )

    return findings
