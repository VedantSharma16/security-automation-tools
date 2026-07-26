"""Active, non-destructive probes for reflected XSS and error-based SQLi.

These checks send one extra request per discovered parameter with a benign
marker/payload and inspect the response -- no state-changing payloads, no
blind/time-based techniques, no attempt to exploit anything found. They are
gated behind `--active` in the CLI and require the user to acknowledge
authorized-use-only scanning.
"""

from __future__ import annotations

import re

from ..models import Endpoint, Finding, Severity

CHECK_NAME_XSS = "reflected-xss"
CHECK_NAME_SQLI = "sql-injection"

# A unique-enough marker that's unlikely to appear in a legitimate response,
# so a raw match is a strong reflection signal without needing full HTML
# parsing to rule out encoding.
XSS_MARKER = "wsx9f2b<script>alert(1)</script>"

SQLI_PAYLOAD = "'"

_SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysqli?_",
    r"unclosed quotation mark after the character string",
    r"sqlite3\.OperationalError",
    r"sqlite3\.Warning",
    r"pg_query\(\)\s*:",
    r"postgresql.*syntax error",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"unterminated quoted string",
    r"sqlstate\[",
]
_SQL_ERROR_RE = re.compile("|".join(_SQL_ERROR_SIGNATURES), re.IGNORECASE)


def _probe_url(endpoint: Endpoint, param: str, value: str) -> str:
    from urllib.parse import urlencode

    params = dict(endpoint.params)
    params[param] = value
    return f"{endpoint.url}?{urlencode(params)}"


def check_reflected_xss(endpoint: Endpoint, param: str, status: int, body: str, probe_url: str) -> Finding | None:
    if status == 200 and XSS_MARKER in body:
        return Finding(
            check=CHECK_NAME_XSS,
            severity=Severity.HIGH,
            title=f"Possible reflected XSS via '{param}' parameter",
            url=probe_url,
            detail=f"An unencoded marker payload injected into '{param}' was "
            "reflected verbatim in the response body.",
            evidence=XSS_MARKER,
            recommendation="Context-appropriately encode/escape all user "
            f"input reflected into HTML output; validate/allow-list '{param}' "
            "server-side; consider a Content-Security-Policy as defense in depth.",
        )
    return None


def check_sql_injection(endpoint: Endpoint, param: str, status: int, body: str, probe_url: str) -> Finding | None:
    match = _SQL_ERROR_RE.search(body)
    if match:
        return Finding(
            check=CHECK_NAME_SQLI,
            severity=Severity.CRITICAL,
            title=f"Possible SQL injection via '{param}' parameter",
            url=probe_url,
            detail=f"Injecting a single quote into '{param}' produced a "
            "database error message in the response, indicating unsanitized "
            "input reaches a SQL query.",
            evidence=match.group(0),
            recommendation="Use parameterized queries / prepared statements "
            f"for all queries built from '{param}'; never string-concatenate "
            "user input into SQL; disable verbose DB error output in production.",
        )
    return None


def build_probes(endpoint: Endpoint) -> list:
    """Yield (param, payload_kind, probe_url) tuples for every parameter."""
    probes = []
    for param in endpoint.params:
        probes.append((param, "xss", _probe_url(endpoint, param, XSS_MARKER)))
        probes.append((param, "sqli", _probe_url(endpoint, param, SQLI_PAYLOAD)))
    return probes
