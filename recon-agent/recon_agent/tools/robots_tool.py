"""robots.txt reconnaissance: passively reads a target's own disclosed
Disallow rules for paths that hint at sensitive functionality.

This never probes the disallowed paths themselves — it only reads the
publicly-served robots.txt, which is intended to be fetched by any client.
"""
from __future__ import annotations

from typing import Callable, List
from urllib.parse import urljoin

from ..models import Finding, ToolResult

SENSITIVE_HINTS = (
    "admin",
    "backup",
    "config",
    "wp-admin",
    "wp-login",
    ".git",
    ".env",
    "phpmyadmin",
    "internal",
    "staging",
    "debug",
    "api-docs",
    "swagger",
)


class FetchResult:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


FetchFn = Callable[[str], FetchResult]


def _default_fetch(url: str) -> FetchResult:
    import requests  # imported lazily: only required when actually fetching

    resp = requests.get(url, timeout=8)
    return FetchResult(status_code=resp.status_code, text=resp.text or "")


def run(base_url: str, fetch_fn: FetchFn = _default_fetch) -> ToolResult:
    robots_url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
    try:
        result = fetch_fn(robots_url)
    except Exception as exc:
        return ToolResult(tool="robots", data={"error": str(exc)}, findings=[])

    if result.status_code != 200:
        return ToolResult(
            tool="robots",
            data={"status_code": result.status_code, "disallowed": []},
            findings=[],
        )

    disallowed = _parse_disallow(result.text)
    findings = analyze_disallowed(disallowed)
    return ToolResult(tool="robots", data={"status_code": 200, "disallowed": disallowed}, findings=findings)


def _parse_disallow(text: str) -> List[str]:
    paths: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                paths.append(path)
    return paths


def analyze_disallowed(paths: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    flagged = [p for p in paths if any(hint in p.lower() for hint in SENSITIVE_HINTS)]
    if flagged:
        findings.append(
            Finding(
                tool="robots",
                severity="low",
                title="robots.txt discloses sensitive-looking paths",
                detail=f"Disallowed paths that may hint at sensitive functionality: {', '.join(flagged)}.",
                recommendation=(
                    "robots.txt is not an access control mechanism; ensure these paths enforce "
                    "their own authentication/authorization rather than relying on obscurity."
                ),
            )
        )
    return findings
