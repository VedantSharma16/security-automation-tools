"""HTTP response header reconnaissance and security-header analysis.

The network call is isolated behind `fetch_fn` so `analyze_headers` (the part
worth testing thoroughly) never needs a real HTTP request.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from ..models import Finding, ToolResult


class FetchResult:
    def __init__(self, url: str, status_code: int, headers: Dict[str, str]):
        self.url = url
        self.status_code = status_code
        self.headers = dict(headers)


FetchFn = Callable[[str], FetchResult]


def _default_fetch(url: str) -> FetchResult:
    import requests  # imported lazily: only required when actually fetching

    resp = requests.get(url, timeout=8, allow_redirects=True)
    return FetchResult(url=resp.url, status_code=resp.status_code, headers=dict(resp.headers))


def normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def run(target: str, fetch_fn: FetchFn = _default_fetch) -> ToolResult:
    url = normalize_url(target)
    try:
        result = fetch_fn(url)
    except Exception as exc:
        return ToolResult(
            tool="http_headers",
            data={"error": str(exc)},
            findings=[
                Finding(
                    tool="http_headers",
                    severity="info",
                    title="HTTP request failed",
                    detail=f"Could not fetch {url}: {exc}",
                    recommendation="Verify the target is reachable and the URL is correct.",
                )
            ],
        )

    findings = analyze_headers(result.url, result.headers)
    data = {"final_url": result.url, "status_code": result.status_code, "headers": result.headers}
    return ToolResult(tool="http_headers", data=data, findings=findings)


def _get(headers: Dict[str, str], name: str) -> Optional[str]:
    lowered = {k.lower(): v for k, v in headers.items()}
    return lowered.get(name.lower())


def analyze_headers(url: str, headers: Dict[str, str]) -> List[Finding]:
    findings: List[Finding] = []
    scheme = urlparse(url).scheme

    if scheme != "https":
        findings.append(
            Finding(
                tool="http_headers",
                severity="high",
                title="Site not served over HTTPS",
                detail=f"Final URL {url} uses '{scheme}'.",
                recommendation="Serve all traffic over HTTPS and redirect HTTP to HTTPS.",
            )
        )

    hsts = _get(headers, "Strict-Transport-Security")
    if scheme == "https" and not hsts:
        findings.append(
            Finding(
                tool="http_headers",
                severity="medium",
                title="Missing Strict-Transport-Security header",
                detail="No HSTS header was returned on an HTTPS response.",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            )
        )

    csp = _get(headers, "Content-Security-Policy")
    if not csp:
        findings.append(
            Finding(
                tool="http_headers",
                severity="medium",
                title="Missing Content-Security-Policy header",
                detail="No CSP header was returned.",
                recommendation="Define a Content-Security-Policy to mitigate XSS and data-injection attacks.",
            )
        )

    xcto = _get(headers, "X-Content-Type-Options")
    if not xcto or xcto.lower() != "nosniff":
        findings.append(
            Finding(
                tool="http_headers",
                severity="low",
                title="Missing X-Content-Type-Options header",
                detail="Header is missing or not set to 'nosniff'.",
                recommendation="Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks.",
            )
        )

    xfo = _get(headers, "X-Frame-Options")
    frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
    if not xfo and not frame_ancestors:
        findings.append(
            Finding(
                tool="http_headers",
                severity="medium",
                title="Missing clickjacking protection",
                detail="Neither X-Frame-Options nor a CSP frame-ancestors directive was found.",
                recommendation="Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
            )
        )

    referrer_policy = _get(headers, "Referrer-Policy")
    if not referrer_policy:
        findings.append(
            Finding(
                tool="http_headers",
                severity="low",
                title="Missing Referrer-Policy header",
                detail="No Referrer-Policy header was found.",
                recommendation="Add a Referrer-Policy such as 'strict-origin-when-cross-origin'.",
            )
        )

    server = _get(headers, "Server")
    xpb = _get(headers, "X-Powered-By")
    if server or xpb:
        disclosed = ", ".join(v for v in (server, xpb) if v)
        findings.append(
            Finding(
                tool="http_headers",
                severity="info",
                title="Server/technology banner disclosed",
                detail=f"Response discloses: {disclosed}.",
                recommendation="Suppress or generalize version-revealing banners to reduce fingerprinting.",
            )
        )

    acao = _get(headers, "Access-Control-Allow-Origin")
    acac = _get(headers, "Access-Control-Allow-Credentials")
    if acao == "*" and acac and acac.lower() == "true":
        findings.append(
            Finding(
                tool="http_headers",
                severity="critical",
                title="Permissive CORS combined with credentials",
                detail=(
                    "Access-Control-Allow-Origin: * is combined with "
                    "Access-Control-Allow-Credentials: true."
                ),
                recommendation=(
                    "Never combine a wildcard ACAO with credentialed CORS; echo a validated "
                    "origin allowlist instead."
                ),
            )
        )
    elif acao == "*":
        findings.append(
            Finding(
                tool="http_headers",
                severity="low",
                title="Wildcard CORS policy",
                detail="Access-Control-Allow-Origin is set to '*'.",
                recommendation=(
                    "Restrict Access-Control-Allow-Origin to a known set of trusted origins "
                    "if the API is not meant to be public."
                ),
            )
        )

    set_cookie = _get(headers, "Set-Cookie")
    if set_cookie:
        cookie_lower = set_cookie.lower()
        if "secure" not in cookie_lower and scheme == "https":
            findings.append(
                Finding(
                    tool="http_headers",
                    severity="medium",
                    title="Cookie missing Secure flag",
                    detail="A Set-Cookie header was returned without the 'Secure' attribute.",
                    recommendation="Add the 'Secure' attribute to all cookies on an HTTPS site.",
                )
            )
        if "httponly" not in cookie_lower:
            findings.append(
                Finding(
                    tool="http_headers",
                    severity="medium",
                    title="Cookie missing HttpOnly flag",
                    detail="A Set-Cookie header was returned without the 'HttpOnly' attribute.",
                    recommendation="Add 'HttpOnly' to session cookies to block access via client-side JavaScript.",
                )
            )
        if "samesite" not in cookie_lower:
            findings.append(
                Finding(
                    tool="http_headers",
                    severity="low",
                    title="Cookie missing SameSite attribute",
                    detail="A Set-Cookie header was returned without a 'SameSite' attribute.",
                    recommendation="Set 'SameSite=Lax' or 'Strict' to mitigate CSRF.",
                )
            )

    return findings
