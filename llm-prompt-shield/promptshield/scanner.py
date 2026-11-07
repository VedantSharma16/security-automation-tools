from __future__ import annotations

import re

from .models import Finding, ScanResult, Severity
from .normalize import count_invisible, decode_base64_blobs, normalize
from .rules import RULES, Rule

_WEIGHT = {Severity.LOW: 5, Severity.MEDIUM: 15, Severity.HIGH: 35, Severity.CRITICAL: 60}
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _excerpt(text: str, start: int, end: int, width: int = 60) -> str:
    seg = text[max(0, start - 10): min(len(text), end + 10)]
    return seg[:width * 2].strip()


def _mask(s: str) -> str:
    """Never echo full secrets into reports."""
    return s if len(s) <= 12 else s[:6] + "…" + s[-2:]


def _apply_rules(text: str, direction: str, decoded: bool, rules: list[Rule]) -> list[Finding]:
    found: list[Finding] = []
    for rule in rules:
        if direction not in rule.directions:
            continue
        m = rule.pattern.search(text)
        if m:
            ex = _excerpt(text, m.start(), m.end())
            if rule.category in ("secret", "pii"):
                ex = _mask(m.group(0))
            found.append(Finding(rule.id, rule.category, rule.severity, rule.description, ex, rule.owasp, decoded))
    for m in _CARD.finditer(text):
        if direction in ("input", "output") and luhn_ok(m.group(0)):
            found.append(Finding("PII-003", "pii", Severity.HIGH, "Payment card number (Luhn-valid)",
                                 _mask(m.group(0)), "LLM06:Sensitive Info Disclosure", decoded))
            break
    return found


def scan(text: str, direction: str = "input", rules: list[Rule] | None = None) -> ScanResult:
    """Scan text flowing into ('input') or out of ('output') an LLM.

    Verdict policy: any HIGH/CRITICAL finding blocks; MEDIUM findings need review.
    """
    if direction not in ("input", "output"):
        raise ValueError("direction must be 'input' or 'output'")
    rules = RULES if rules is None else rules
    findings: list[Finding] = []

    hidden = count_invisible(text)
    if hidden >= 3:
        findings.append(Finding("OB-001", "obfuscation", Severity.MEDIUM,
                                "Invisible/zero-width/tag characters present",
                                f"{hidden} invisible characters", "LLM01:Prompt Injection"))

    norm = normalize(text)
    findings += _apply_rules(norm, direction, False, rules)

    for blob in decode_base64_blobs(text):
        inner = _apply_rules(normalize(blob), direction, True, rules)
        if inner:
            findings.append(Finding("OB-002", "obfuscation", Severity.HIGH,
                                    "Base64-encoded payload containing flagged content",
                                    _mask(blob), "LLM01:Prompt Injection", True))
            findings += inner

    # de-duplicate by (rule, decoded)
    seen, unique = set(), []
    for f in findings:
        key = (f.rule_id, f.decoded)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    score = min(100, sum(_WEIGHT[f.severity] for f in unique))
    top = max((f.severity for f in unique), default=None)
    if top is not None and top >= Severity.HIGH:
        verdict = "block"
    elif top == Severity.MEDIUM:
        verdict = "review"
    else:
        verdict = "allow"
    return ScanResult(direction, unique, score, verdict)
