"""Information-disclosure checks on response headers (server/framework fingerprinting)."""

from __future__ import annotations

import re

from ..models import Finding, ScanTarget

_VERSION_RE = re.compile(r"\d+\.\d+")

_DISCLOSURE_HEADERS = (
    ("x-powered-by", "X-Powered-By"),
    ("x-aspnet-version", "X-AspNet-Version"),
    ("x-aspnetmvc-version", "X-AspNetMvc-Version"),
    ("x-generator", "X-Generator"),
)


def check_info_disclosure(target: ScanTarget) -> list[Finding]:
    findings: list[Finding] = []

    server = target.get_header("server")
    if server and _VERSION_RE.search(server):
        findings.append(
            Finding(
                id="disclosure-server-version",
                title="Server header discloses software version",
                severity="low",
                category="disclosure",
                description=(
                    f'The Server header ("{server}") includes a version number, '
                    "which helps an attacker pick known CVEs to try against this "
                    "stack without any further probing."
                ),
                remediation="Configure the web server to omit or minimize the Server header (e.g. `server_tokens off;` in nginx).",
                evidence=server,
            )
        )

    for header_key, display_name in _DISCLOSURE_HEADERS:
        value = target.get_header(header_key)
        if value:
            findings.append(
                Finding(
                    id=f"disclosure-{header_key}",
                    title=f"{display_name} header discloses backend technology",
                    severity="low",
                    category="disclosure",
                    description=(
                        f'"{display_name}: {value}" reveals implementation details '
                        "that aid attacker reconnaissance and have no benefit to "
                        "legitimate clients."
                    ),
                    remediation=f"Remove the {display_name} header from responses.",
                    evidence=f"{display_name}: {value}",
                )
            )

    return findings
