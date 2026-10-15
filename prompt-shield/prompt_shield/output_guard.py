"""Output guard: catch secrets, canary leaks, and exfiltration links in model responses."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "generic_api_key": re.compile(r"(?i)\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+]{16,}"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
}
_MD_IMG = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)")


@dataclass
class OutputFinding:
    kind: str
    detail: str


def make_canary(prefix: str = "CANARY") -> str:
    """Token to embed in the system prompt; if it appears in output, the prompt leaked."""
    return f"{prefix}-{secrets.token_hex(6)}"


def guard_output(text: str, canary: str | None = None,
                 allowed_hosts: frozenset[str] = frozenset()) -> list[OutputFinding]:
    out: list[OutputFinding] = []
    if canary and canary in text:
        out.append(OutputFinding("system_prompt_leak", "canary token present in response"))
    for name, pat in SECRET_PATTERNS.items():
        if pat.search(text):
            out.append(OutputFinding("secret", name))
    for m in _MD_IMG.finditer(text):
        url = m.group(1)
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
        if host not in allowed_hosts and ("?" in url):
            out.append(OutputFinding("exfil_link", f"external image with query string: {host}"))
    return out
