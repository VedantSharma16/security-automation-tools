"""Cross-Origin Resource Sharing misconfiguration probe.

Sends a request with a made-up, clearly non-affiliated Origin header and
inspects whether the server reflects it back — the classic sign of a CORS
policy that trusts "any origin" instead of an allowlist.
"""

from __future__ import annotations

from .fetch import Fetcher
from .findings import Finding, Severity

PROBE_ORIGIN = "https://cors-probe.invalid-test-origin.example"


def check_cors(fetcher: Fetcher, url: str) -> list[Finding]:
    result = fetcher.get(url, extra_headers={"Origin": PROBE_ORIGIN})
    if not result.ok:
        return []

    allow_origin = _header(result.headers, "Access-Control-Allow-Origin")
    allow_credentials = (_header(result.headers, "Access-Control-Allow-Credentials") or "").lower() == "true"

    if allow_origin is None:
        return []

    reflects_arbitrary_origin = allow_origin == PROBE_ORIGIN
    wildcard = allow_origin == "*"

    if reflects_arbitrary_origin and allow_credentials:
        return [
            Finding(
                id="cors-reflected-origin-with-credentials",
                title="CORS reflects arbitrary Origin with credentials allowed",
                severity=Severity.CRITICAL,
                owasp_category="A01:2021 Broken Access Control",
                description="The server reflects any Origin header back in "
                "Access-Control-Allow-Origin and also sets "
                "Access-Control-Allow-Credentials: true. Any website can issue "
                "credentialed cross-origin requests (cookies/auth included) and read "
                "the response — a near-total bypass of the same-origin policy.",
                evidence=f"Origin: {PROBE_ORIGIN} -> "
                f"Access-Control-Allow-Origin: {allow_origin}, "
                f"Access-Control-Allow-Credentials: true",
                remediation="Validate Origin against an explicit allowlist server-side "
                "before echoing it, and never combine a reflected/wildcard origin with "
                "Access-Control-Allow-Credentials: true.",
            )
        ]

    if reflects_arbitrary_origin:
        return [
            Finding(
                id="cors-reflected-origin",
                title="CORS reflects arbitrary Origin",
                severity=Severity.MEDIUM,
                owasp_category="A01:2021 Broken Access Control",
                description="The server echoes back whatever Origin header is sent "
                "instead of validating it against an allowlist. No credentials were "
                "observed being allowed, but this still permits any site to read "
                "non-credentialed responses cross-origin.",
                evidence=f"Origin: {PROBE_ORIGIN} -> "
                f"Access-Control-Allow-Origin: {allow_origin}",
                remediation="Validate Origin against an explicit allowlist instead of "
                "reflecting the request header verbatim.",
            )
        ]

    if wildcard and allow_credentials:
        # Not actually spec-legal (browsers reject ACAO:* with credentials), but a
        # server sending it is still a misconfiguration worth flagging.
        return [
            Finding(
                id="cors-wildcard-with-credentials",
                title="CORS wildcard origin combined with credentials flag",
                severity=Severity.HIGH,
                owasp_category="A01:2021 Broken Access Control",
                description="The server sends Access-Control-Allow-Origin: * together "
                "with Access-Control-Allow-Credentials: true. Browsers reject this "
                "combination, but it signals a broken CORS policy that should be "
                "fixed before it silently becomes exploitable (e.g. after a future "
                "change reflects Origin instead of using '*').",
                evidence="Access-Control-Allow-Origin: *, "
                "Access-Control-Allow-Credentials: true",
                remediation="Never pair a wildcard/reflected origin with "
                "Access-Control-Allow-Credentials: true.",
            )
        ]

    if wildcard:
        return [
            Finding(
                id="cors-wildcard-origin",
                title="CORS allows any origin (wildcard)",
                severity=Severity.INFO,
                owasp_category="A01:2021 Broken Access Control",
                description="Access-Control-Allow-Origin is set to '*'. This is a "
                "reasonable choice for a fully public, unauthenticated API, but is "
                "worth confirming no cookie/token-based auth relies on this endpoint.",
                evidence="Access-Control-Allow-Origin: *",
                remediation="Confirm this endpoint serves only public data; scope to "
                "an allowlist if it ever handles authenticated requests.",
            )
        ]

    return []


def _header(headers: dict[str, str], name: str) -> str | None:
    name_lower = name.lower()
    for key, value in headers.items():
        if key.lower() == name_lower:
            return value
    return None
