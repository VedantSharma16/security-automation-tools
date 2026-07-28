"""HTTP security header auditing and server banner disclosure checks.

Like `portscan`, this performs an active HTTP request against the target
and is gated behind the CLI's authorization flag.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request

from .models import Finding

USER_AGENT = "attack-surface-mapper/0.1 (authorized-recon-tool)"

# header -> (severity if missing, human description)
_REQUIRED_HEADERS: dict[str, tuple[str, str]] = {
    "content-security-policy": (
        "medium",
        "No Content-Security-Policy header — reduces defense-in-depth against XSS/injection.",
    ),
    "x-content-type-options": (
        "low",
        "Missing X-Content-Type-Options: nosniff — browser may MIME-sniff responses.",
    ),
    "referrer-policy": (
        "low",
        "No Referrer-Policy header — full URLs may leak to third parties via the Referer header.",
    ),
    "permissions-policy": (
        "low",
        "No Permissions-Policy header — browser features are not explicitly restricted.",
    ),
}

# Headers whose *value* discloses implementation details useful for
# fingerprinting/exploitation (e.g. "Apache/2.4.41 (Ubuntu)").
_BANNER_HEADERS = ("server", "x-powered-by")
_VERSION_HINT = re.compile(r"\d+\.\d+")


def fetch_headers(
    url: str, timeout: float = 10.0, opener=urllib.request.urlopen
) -> tuple[int | None, dict[str, str]]:
    """Fetch response headers for `url`. Returns (status_code, headers) or (None, {}) on failure."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    try:
        with opener(request, timeout=timeout) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            return response.status, headers
    except urllib.error.HTTPError as exc:
        # An HTTP error status still carries real, inspectable headers.
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, headers
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, {}


def audit_headers(headers: dict[str, str], scheme: str = "https") -> list[Finding]:
    """Check response headers against the required security-header baseline."""
    findings: list[Finding] = []
    lowered = {k.lower(): v for k, v in headers.items()}

    if scheme == "https" and "strict-transport-security" not in lowered:
        findings.append(
            Finding(
                category="header",
                severity="high",
                title="Missing Strict-Transport-Security",
                detail="HTTPS is available but HSTS is not enforced — allows protocol downgrade "
                "to plaintext HTTP on subsequent visits.",
            )
        )

    csp = lowered.get("content-security-policy", "")
    has_frame_defense = "x-frame-options" in lowered or "frame-ancestors" in csp
    if not has_frame_defense:
        findings.append(
            Finding(
                category="header",
                severity="medium",
                title="Missing clickjacking protection",
                detail="Neither X-Frame-Options nor a CSP frame-ancestors directive is set — "
                "the page can be framed by another origin.",
            )
        )

    for header, (severity, detail) in _REQUIRED_HEADERS.items():
        if header not in lowered:
            findings.append(
                Finding(
                    category="header",
                    severity=severity,
                    title=f"Missing {header}",
                    detail=detail,
                )
            )

    return findings


def audit_banner(headers: dict[str, str]) -> list[Finding]:
    """Flag Server/X-Powered-By headers that disclose specific software versions."""
    findings: list[Finding] = []
    lowered = {k.lower(): v for k, v in headers.items()}

    for header in _BANNER_HEADERS:
        value = lowered.get(header)
        if value and _VERSION_HINT.search(value):
            findings.append(
                Finding(
                    category="banner",
                    severity="low",
                    title=f"Version disclosure via {header}",
                    detail=f"{header}: {value} — narrows down exploit targeting for an attacker.",
                )
            )

    return findings
