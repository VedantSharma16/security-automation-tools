"""Cross-Origin Resource Sharing misconfiguration checks.

Relies on ``target.cors_test_headers``, the response headers captured when
the fetcher re-requested the URL with an ``Origin`` header set to an
attacker-controlled-looking test origin (see ``fetcher.fetch_target``).
"""

from __future__ import annotations

from ..models import Finding, ScanTarget


def check_cors(target: ScanTarget) -> list[Finding]:
    if not target.cors_test_headers:
        return []

    headers = {k.lower(): v for k, v in target.cors_test_headers.items()}
    allow_origin = headers.get("access-control-allow-origin")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"

    if allow_origin is None:
        return []

    reflects_test_origin = (
        target.cors_test_origin is not None and allow_origin == target.cors_test_origin
    )

    if reflects_test_origin and allow_credentials:
        return [
            Finding(
                id="cors-reflected-origin-with-credentials",
                title="CORS reflects arbitrary Origin with credentials allowed",
                severity="critical",
                category="cors",
                description=(
                    "The server echoes any Origin header back in "
                    "Access-Control-Allow-Origin and also sends "
                    "Access-Control-Allow-Credentials: true. Any website can now "
                    "make authenticated, credentialed requests on behalf of a "
                    "logged-in victim and read the response — effectively a "
                    "cross-origin account takeover primitive."
                ),
                remediation=(
                    "Validate Origin against an explicit allow-list before "
                    "reflecting it, or drop Access-Control-Allow-Credentials if "
                    "the API doesn't need cookie-based auth from other origins."
                ),
                evidence=f"Origin: {target.cors_test_origin} -> Access-Control-Allow-Origin: {allow_origin}",
            )
        ]

    if reflects_test_origin:
        return [
            Finding(
                id="cors-reflected-origin",
                title="CORS reflects arbitrary Origin values",
                severity="medium",
                category="cors",
                description=(
                    "The server reflects any Origin header back in "
                    "Access-Control-Allow-Origin without validating it against "
                    "an allow-list. No credentials are currently allowed, which "
                    "limits impact, but any site can still read non-credentialed "
                    "responses."
                ),
                remediation="Validate Origin against an explicit allow-list.",
                evidence=f"Origin: {target.cors_test_origin} -> Access-Control-Allow-Origin: {allow_origin}",
            )
        ]

    if allow_origin == "*":
        if allow_credentials:
            return [
                Finding(
                    id="cors-wildcard-with-credentials",
                    title="CORS wildcard origin combined with credentials",
                    severity="high",
                    category="cors",
                    description=(
                        "Access-Control-Allow-Origin: * is set alongside "
                        "Access-Control-Allow-Credentials: true. This combination "
                        "is invalid per the Fetch spec and browsers will reject "
                        "the credentialed request, but it signals a "
                        "misunderstanding of CORS that often masks a real "
                        "misconfiguration elsewhere (e.g. origin reflection)."
                    ),
                    remediation=(
                        "Never pair a wildcard origin with credentialed CORS; "
                        "use an explicit allow-list instead."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {allow_origin}",
                )
            ]
        return [
            Finding(
                id="cors-wildcard-origin",
                title="CORS allows any origin (Access-Control-Allow-Origin: *)",
                severity="info",
                category="cors",
                description=(
                    "The endpoint allows cross-origin reads from any website. "
                    "This is often intentional for a public API, but confirm no "
                    "sensitive, non-public data is served here."
                ),
                remediation="Restrict to an explicit origin allow-list if this endpoint returns non-public data.",
                evidence=f"Access-Control-Allow-Origin: {allow_origin}",
            )
        ]

    return []
