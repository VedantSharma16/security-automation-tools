"""Scanner: normalize -> match rules across views -> score -> verdict."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .normalize import decode_payloads, leet_fold, normalize
from .rules import RULES, SECRET_RULES, Rule

BLOCK_THRESHOLD = 8
REVIEW_THRESHOLD = 5


@dataclass
class Finding:
    rule_id: str
    name: str
    category: str
    atlas: str
    severity: int
    evidence: str
    view: str  # which view matched: raw | leet | base64 | hex | rot13

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    score: int
    verdict: str  # allow | review | block
    findings: list[Finding] = field(default_factory=list)
    obfuscation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"score": self.score, "verdict": self.verdict,
                "obfuscation": self.obfuscation,
                "findings": [f.to_dict() for f in self.findings]}


def _clip(s: str, n: int = 80) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _redact(s: str) -> str:
    return s[:4] + "…[redacted]" if len(s) > 8 else "[redacted]"


class Scanner:
    """Scan untrusted text (``mode="input"``) or model output (``mode="output"``).

    Input mode looks for injection/jailbreak/exfil attempts; output mode looks
    for leaked secrets/PII and system-prompt canaries. Evidence for secret
    findings is always redacted.
    """

    def __init__(self, block_threshold: int = BLOCK_THRESHOLD,
                 review_threshold: int = REVIEW_THRESHOLD,
                 extra_rules: list[Rule] | None = None,
                 canaries: list[str] | None = None):
        self.block_threshold = block_threshold
        self.review_threshold = review_threshold
        self.extra_rules = extra_rules or []
        self.canaries = canaries or []

    def scan(self, text: str, mode: str = "input") -> ScanResult:
        if mode not in ("input", "output"):
            raise ValueError("mode must be 'input' or 'output'")
        canon, flags = normalize(text)
        views: list[tuple[str, str]] = [("raw", canon)]
        folded = leet_fold(canon)
        if folded != canon:
            views.append(("leet", folded))
        for enc, dec in decode_payloads(canon):
            flags.append(f"encoded_{enc}")
            views.append((enc, normalize(dec)[0]))

        rules = (SECRET_RULES if mode == "output" else RULES + SECRET_RULES) + self.extra_rules
        seen: dict[str, Finding] = {}
        for view, body in views:
            for rule in rules:
                if rule.id in seen:
                    continue
                m = rule.pattern.search(body)
                if m:
                    ev = _redact(m.group(0)) if rule.id.startswith("SE-") else _clip(m.group(0))
                    seen[rule.id] = Finding(rule.id, rule.name, rule.category, rule.atlas,
                                            rule.severity, ev, view)
        if mode == "output":
            for c in self.canaries:
                if c and c in text:
                    seen["CN-001"] = Finding("CN-001", "System prompt canary leaked",
                                             "LLM07 System Prompt Leakage", "AML.T0056", 10,
                                             "[canary]", "raw")
        findings = sorted(seen.values(), key=lambda f: -f.severity)
        score = self._score(findings, flags)
        verdict = ("block" if score >= self.block_threshold
                   else "review" if score >= self.review_threshold else "allow")
        return ScanResult(score, verdict, findings, sorted(set(flags)))

    @staticmethod
    def _score(findings: list[Finding], flags: list[str]) -> int:
        if not findings:
            # obfuscation alone is suspicious but not conclusive
            return 3 if flags else 0
        score = findings[0].severity
        score += min(2, len(findings) - 1)          # corroboration
        if flags:
            score += 2                              # hiding the attack is intent
        return min(score, 10)
