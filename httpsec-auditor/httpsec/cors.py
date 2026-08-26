"""Analysis of Cross-Origin Resource Sharing (CORS) response headers.

The caller is expected to have made a request that sent a probe `Origin`
header (an arbitrary, attacker-controlled-looking origin) and captured the
response headers; this module only reasons about the resulting headers, so
it stays pure and offline-testable.
"""

from __future__ import annotations

from .models import Finding


def _get(headers: dict, name: str) -> str | None:
    lname = name.lower()
    for key, value in headers.items():
        if key.lower() == lname:
            return value
    return None


def analyze_cors(headers: dict, probe_origin: str) -> list[Finding]:
    findings: list[Finding] = []

    allow_origin = _get(headers, "Access-Control-Allow-Origin")
    if allow_origin is None:
        return findings  # CORS not enabled for this resource; nothing to flag

    allow_credentials = (_get(headers, "Access-Control-Allow-Credentials") or "").lower() == "true"

    if allow_origin == "*" and allow_credentials:
        findings.append(
            Finding(
                id="cors-wildcard-with-credentials",
                category="cors",
                severity="critical",
                title="CORS allows '*' origin together with credentials",
                description=(
                    "`Access-Control-Allow-Origin: *` combined with "
                    "`Access-Control-Allow-Credentials: true` is an invalid, "
                    "dangerous combination: spec-compliant browsers reject it, "
                    "but it signals a misconfigured CORS policy that a proxy or "
                    "older client may still honor, exposing authenticated data "
                    "to any origin."
                ),
                remediation="Never pair a wildcard origin with credentialed CORS. Return an explicit, validated origin instead.",
                evidence=f"Access-Control-Allow-Origin: {allow_origin}; Access-Control-Allow-Credentials: {allow_credentials}",
            )
        )
    elif allow_origin == probe_origin:
        severity = "critical" if allow_credentials else "high"
        findings.append(
            Finding(
                id="cors-reflects-arbitrary-origin",
                category="cors",
                severity=severity,
                title="CORS policy reflects an arbitrary Origin",
                description=(
                    f"The server echoed back an unrecognized probe origin "
                    f"({probe_origin!r}) verbatim in Access-Control-Allow-Origin"
                    + (" with credentials allowed" if allow_credentials else "")
                    + ". This effectively allows any website to make "
                    "cross-origin requests to this endpoint"
                    + (" and read the response using the victim's session cookies."
                       if allow_credentials else ", reading the response body.")
                ),
                remediation=(
                    "Validate the Origin header against an explicit allowlist "
                    "server-side before reflecting it; never reflect unknown "
                    "origins, especially alongside Allow-Credentials."
                ),
                evidence=f"probe Origin: {probe_origin} -> Access-Control-Allow-Origin: {allow_origin}",
            )
        )
    elif allow_origin == "*":
        findings.append(
            Finding(
                id="cors-wildcard-origin",
                category="cors",
                severity="low",
                title="CORS allows any origin ('*')",
                description="Any website can read this endpoint's response via cross-origin fetch/XHR (no credentials are shared, but data exposure may still matter for non-public resources).",
                remediation="If this endpoint returns non-public data, restrict Access-Control-Allow-Origin to an explicit allowlist.",
                evidence=f"Access-Control-Allow-Origin: {allow_origin}",
            )
        )

    allow_headers = _get(headers, "Access-Control-Allow-Headers") or ""
    if allow_headers.strip() == "*" and allow_credentials:
        findings.append(
            Finding(
                id="cors-wildcard-headers-with-credentials",
                category="cors",
                severity="medium",
                title="CORS allows any request header together with credentials",
                description="A wildcard Access-Control-Allow-Headers alongside credentialed requests broadens the attack surface for custom-header-based abuse.",
                remediation="Enumerate the specific headers the API needs instead of using a wildcard.",
                evidence=f"Access-Control-Allow-Headers: {allow_headers}",
            )
        )

    return findings
