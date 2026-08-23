"""HTTP security header analysis.

Checks a target's response headers against the common browser-enforced
security controls (HSTS, CSP, frame/content-type protections, cookie
flags) and flags information disclosure via the `Server`/`X-Powered-By`
headers. This mirrors what tools like Mozilla Observatory / securityheaders.com
check, implemented from scratch against the stdlib.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from .findings import Finding


class FetchError(Exception):
    """Raised when the target could not be reached at all."""


def _default_fetcher(url: str, timeout: float):
    request = urllib.request.Request(url, headers={"User-Agent": "websec-recon/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (deliberate, user-supplied recon target)
        return response.status, dict(response.headers), response.geturl()


def fetch_headers(url: str, timeout: float = 5.0, fetcher=_default_fetcher) -> dict:
    """Fetch `url` and return {status, headers, final_url}.

    Raises FetchError on any connection/HTTP-level failure. HTTP error
    responses (4xx/5xx) still carry headers worth analyzing, so those are
    captured via urllib.error.HTTPError rather than treated as a failure.
    """
    try:
        status, headers, final_url = fetcher(url, timeout)
    except urllib.error.HTTPError as exc:
        status, headers, final_url = exc.code, dict(exc.headers or {}), url
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise FetchError(f"could not fetch {url}: {exc}") from exc

    return {"status": status, "headers": headers, "final_url": final_url}


# header -> (severity if missing, human-readable rationale)
_REQUIRED_HEADERS = {
    "Strict-Transport-Security": (
        "high",
        "Without HSTS, users can be downgraded to plaintext HTTP and MITM'd (e.g. on hostile Wi-Fi).",
    ),
    "Content-Security-Policy": (
        "medium",
        "Without a CSP, the browser has no defense-in-depth against injected/XSS scripts.",
    ),
    "X-Content-Type-Options": (
        "low",
        "Without 'nosniff', browsers may MIME-sniff responses in ways that enable content-type confusion attacks.",
    ),
    "X-Frame-Options": (
        "medium",
        "Without frame protections (or an equivalent CSP frame-ancestors directive), the site may be vulnerable to clickjacking.",
    ),
    "Referrer-Policy": (
        "low",
        "Without a Referrer-Policy, full URLs (potentially containing tokens/paths) may leak to third-party destinations via the Referer header.",
    ),
}

_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def analyze_headers(result: dict) -> list[Finding]:
    headers = {k: v for k, v in result["headers"].items()}
    # Case-insensitive lookup, matching HTTP header semantics.
    lower_map = {k.lower(): (k, v) for k, v in headers.items()}

    findings: list[Finding] = []

    for name, (severity, rationale) in _REQUIRED_HEADERS.items():
        if name.lower() in lower_map:
            continue
        # A frame-ancestors CSP directive is an accepted substitute for X-Frame-Options.
        if name == "X-Frame-Options":
            csp = lower_map.get("content-security-policy", ("", ""))[1]
            if "frame-ancestors" in csp.lower():
                continue
        findings.append(
            Finding(
                category="http_headers",
                title=f"Missing {name} header",
                severity=severity,
                description=rationale,
                recommendation=f"Set the {name} response header on {result['final_url']}.",
                evidence={"status": result["status"]},
            )
        )

    for name in _DISCLOSURE_HEADERS:
        if name.lower() in lower_map:
            _, value = lower_map[name.lower()]
            findings.append(
                Finding(
                    category="http_headers",
                    title=f"{name} header discloses software details",
                    severity="info",
                    description=f"{name}: {value}",
                    recommendation=(
                        f"Suppress or genericize the {name} header to avoid handing "
                        "attackers a shortlist of known CVEs to try."
                    ),
                    evidence={name: value},
                )
            )

    for raw_name, raw_value in headers.items():
        if raw_name.lower() != "set-cookie":
            continue
        cookie_lower = raw_value.lower()
        missing_flags = [
            flag
            for flag in ("secure", "httponly", "samesite")
            if flag not in cookie_lower
        ]
        if missing_flags:
            findings.append(
                Finding(
                    category="http_headers",
                    title="Cookie missing security flag(s)",
                    severity="medium",
                    description=(
                        f"A Set-Cookie header is missing: {', '.join(missing_flags)}. "
                        "This increases exposure to session theft via XSS or network interception."
                    ),
                    recommendation="Set Secure, HttpOnly, and SameSite on all session cookies.",
                    evidence={"set_cookie": raw_value, "missing": missing_flags},
                )
            )

    return findings
