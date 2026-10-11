"""Output scanner: secrets, exfil links, and canary leakage in model responses."""
from __future__ import annotations

import re

from .canary import CanaryToken
from .scanner import Finding, Verdict

_PATTERNS = [
    ("OUT-001", "secret_leak", 9, r"\bAKIA[0-9A-Z]{16}\b", "AWS access key ID"),
    ("OUT-002", "secret_leak", 9, r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key material"),
    ("OUT-003", "secret_leak", 8, r"\b(sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9\-]{10,})", "API token"),
    ("OUT-004", "data_exfiltration", 9, r"!\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]+\)", "Markdown image with query string (exfil channel)"),
    ("OUT-005", "pii", 5, r"\b\d{3}-\d{2}-\d{4}\b", "US SSN-shaped number"),
]


def scan_output(text: str, canary: CanaryToken | None = None) -> Verdict:
    findings = []
    for rid, cat, sev, pat, desc in _PATTERNS:
        m = re.search(pat, text)
        if m:
            findings.append(Finding(rid, cat, sev, desc, "LLM02", "output", _redact(m.group(0))))
    if canary and canary.leaked_in(text):
        findings.append(Finding("OUT-900", "prompt_leak", 10, "System prompt canary token leaked",
                                "LLM07", "output", "<canary>"))
    score = max((f.severity for f in findings), default=0)
    action = "block" if score >= 8 else "warn" if score >= 5 else "allow"
    return Verdict(action, score, sorted(findings, key=lambda f: -f.severity))


def _redact(s: str) -> str:
    return s if len(s) <= 8 else s[:4] + "…" + s[-2:]
