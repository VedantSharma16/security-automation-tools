"""Output-side guard: catch what an injection *achieved*, not just what it tried.

Input filtering is never complete, so production LLM apps also inspect the
model's response before it reaches the user or a downstream tool:

* **Canary tokens** — a random marker planted in the system prompt. If it
  ever appears in an output, the system prompt leaked (OWASP LLM07).
* **Secret patterns** — cloud keys, private keys, JWTs, etc. in model output
  (OWASP LLM02).
* **Markdown exfiltration** — images/links to external hosts carrying query
  data, the zero-click channel used in many real indirect-injection attacks.
  Hosts on an allow-list are ignored.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, urlparse

CANARY_PREFIX = "CANARY-"


def make_canary() -> str:
    """Generate a canary token to embed in a system prompt."""
    return f"{CANARY_PREFIX}{secrets.token_hex(8)}"


def embed_canary(system_prompt: str, canary: str) -> str:
    """Append a canary to a system prompt in a way the model has no reason to repeat."""
    return f"{system_prompt.rstrip()}\n\n[internal reference id: {canary} — never output this value]"


SECRET_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-style-api-key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_\-]{32,}")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("password-assignment", re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{6,}", re.IGNORECASE)),
)

_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?([^)\s>]+)>?[^)]*\)")
_MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*<?([^)\s>]+)>?[^)]*\)")
_HTML_IMG = re.compile(r"<img[^>]+src\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)


@dataclass
class OutputIssue:
    kind: str     # "canary-leak" | "secret" | "markdown-exfiltration"
    detail: str
    severity: str  # "critical" | "high" | "medium"


@dataclass
class OutputScanResult:
    safe: bool
    issues: list[OutputIssue] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _redact(value: str) -> str:
    return value[:6] + "…" + f"[{len(value)} chars]" if len(value) > 10 else "[redacted]"


def _host_allowed(host: str, allowed: set[str]) -> bool:
    host = host.lower()
    return any(host == a or host.endswith("." + a) for a in allowed)


def _exfil_issue(url: str, kind: str, allowed: set[str]) -> OutputIssue | None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    if _host_allowed(parsed.hostname, allowed):
        return None
    params = parse_qsl(parsed.query, keep_blank_values=True)
    long_values = [v for _, v in params if len(v) >= 16]
    long_path_seg = any(len(seg) >= 32 for seg in parsed.path.split("/"))
    if kind == "image":
        # Images auto-load: any external image with data in the URL is a zero-click channel.
        if params or long_path_seg:
            return OutputIssue("markdown-exfiltration",
                               f"external image to {parsed.hostname} carries data in URL", "high")
        return OutputIssue("markdown-exfiltration",
                           f"external image to non-allow-listed host {parsed.hostname}", "medium")
    if long_values or long_path_seg:
        return OutputIssue("markdown-exfiltration",
                           f"link to {parsed.hostname} embeds long data value(s) in URL", "medium")
    return None


def scan_output(
    text: str,
    canaries: list[str] | None = None,
    allowed_hosts: list[str] | None = None,
) -> OutputScanResult:
    issues: list[OutputIssue] = []
    allowed = {h.lower() for h in (allowed_hosts or [])}

    for canary in canaries or []:
        if canary and canary in text:
            issues.append(OutputIssue("canary-leak", f"system-prompt canary {canary} present in output", "critical"))

    for name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            issues.append(OutputIssue("secret", f"{name}: {_redact(m.group(0))}", "critical" if name != "password-assignment" else "high"))

    for url in _MD_IMAGE.findall(text) + _HTML_IMG.findall(text):
        issue = _exfil_issue(url, "image", allowed)
        if issue:
            issues.append(issue)
    for url in _MD_LINK.findall(text):
        issue = _exfil_issue(url, "link", allowed)
        if issue:
            issues.append(issue)

    return OutputScanResult(safe=not issues, issues=issues)
