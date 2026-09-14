"""CORS misconfiguration checks based on the response's static CORS headers.

Note: this inspects the CORS headers the server sent on a plain request. A
full CORS audit also probes with attacker-controlled ``Origin`` values to
check whether the server reflects arbitrary origins; that active probing is
out of scope here to keep this a passive, single-request check.
"""

from __future__ import annotations

from http_audit.fetcher import HttpResponse
from http_audit.report import Finding


def check_cors(response: HttpResponse) -> list[Finding]:
    acao = response.get_header("access-control-allow-origin")
    acac = response.get_header("access-control-allow-credentials")

    if acao is None:
        return [Finding("cors", "CORS", "info", "No Access-Control-Allow-Origin header observed on this response.")]

    credentials_enabled = (acac or "").strip().lower() == "true"

    if acao.strip() == "*" and credentials_enabled:
        return [
            Finding(
                "cors",
                "CORS wildcard with credentials",
                "critical",
                "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is 'true'. "
                "Browsers forbid this combination, but servers that emit it are typically reflecting "
                "the request Origin unsafely, which lets any site read authenticated responses.",
                "Return a specific, allow-listed origin instead of '*' whenever credentials are allowed.",
            )
        ]

    if acao.strip() == "*":
        return [
            Finding(
                "cors",
                "CORS wildcard origin",
                "low",
                "Access-Control-Allow-Origin is '*'. Fine for public, non-authenticated APIs; risky otherwise.",
                "Restrict Access-Control-Allow-Origin to an explicit allow-list if the response contains "
                "any non-public or user-specific data.",
            )
        ]

    if credentials_enabled:
        return [
            Finding(
                "cors",
                "CORS credentials enabled",
                "info",
                f"Access-Control-Allow-Origin is scoped to '{acao}' with credentials allowed.",
                "Confirm the allow-listed origin(s) are trusted and the list can't be widened by user input.",
            )
        ]

    return [Finding("cors", "CORS", "pass", f"Access-Control-Allow-Origin is scoped to '{acao}' without credentials.")]
