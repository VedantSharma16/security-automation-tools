"""Guard: scans prompts going in and responses coming out."""
from __future__ import annotations

import re
import secrets

from . import normalize as nz
from .models import Finding, Severity, Verdict
from .rules import CARD_RE, INPUT_RULES, SECRET_PATTERNS, Rule

_WEIGHT = {Severity.LOW: 10, Severity.MEDIUM: 25, Severity.HIGH: 45, Severity.CRITICAL: 70}


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def _score(findings: list[Finding]) -> int:
    """Diminishing-returns sum so many weak signals don't dwarf one strong one."""
    weights = sorted((_WEIGHT[f.severity] for f in findings), reverse=True)
    return min(100, int(sum(w * (0.6 ** i) for i, w in enumerate(weights))))


class Guard:
    """Rule-based guardrail.

    block_threshold: score at/above which ``Verdict.blocked`` is set.
    canary: optional secret embedded in your system prompt; if it appears in a
        model response the prompt has leaked (see ``new_canary``).
    """

    def __init__(self, block_threshold: int = 40, canary: str | None = None,
                 redact_secrets: bool = True) -> None:
        self.block_threshold = block_threshold
        self.canary = canary
        self.redact_secrets = redact_secrets

    @staticmethod
    def new_canary() -> str:
        return "CANARY-" + secrets.token_hex(8)

    # -- input ---------------------------------------------------------------
    def scan_input(self, text: str) -> Verdict:
        findings: list[Finding] = []
        seen: set[str] = set()

        def add(rule: Rule, evidence: str, suffix: str = "") -> None:
            key = rule.rule_id + suffix
            if key in seen:
                return
            seen.add(key)
            desc = rule.description + (f" ({suffix.strip()})" if suffix else "")
            findings.append(Finding(rule.rule_id, rule.category, rule.severity, desc, evidence[:120]))

        hidden = nz.count_invisible(text)
        if hidden:
            findings.append(Finding("PI-009", "LLM01", Severity.MEDIUM,
                                    "Invisible / bidi control characters present", f"{hidden} chars"))

        base = nz.normalize(text)
        variants = [("", base), ("leetspeak", nz.deleet(base))]
        for decoded in nz.decode_base64_chunks(text):
            variants.append(("base64-decoded", nz.normalize(decoded)))

        for label, variant in variants:
            suffix = f" {label}" if label else ""
            for rule in INPUT_RULES:
                m = rule.pattern.search(variant)
                if m:
                    add(rule, m.group(0), suffix)
                    if label == "base64-decoded":  # hiding payloads in encoding is itself a signal
                        add(Rule("PI-010", "LLM01", Severity.HIGH, "Encoded payload contains injection",
                                 rule.pattern), m.group(0))

        score = _score(findings)
        return Verdict(findings=findings, score=score, blocked=score >= self.block_threshold,
                       sanitized=nz.strip_invisible(text))

    # -- output --------------------------------------------------------------
    def scan_output(self, text: str) -> Verdict:
        findings: list[Finding] = []
        redacted = text

        if self.canary and self.canary in text:
            findings.append(Finding("OUT-000", "LLM07", Severity.CRITICAL,
                                    "System prompt canary leaked", self.canary[:12] + "…"))
            redacted = redacted.replace(self.canary, "[REDACTED:CANARY]")

        for rule in SECRET_PATTERNS:
            for m in rule.pattern.finditer(text):
                findings.append(Finding(rule.rule_id, rule.category, rule.severity,
                                        rule.description, _mask(m.group(0))))
                redacted = redacted.replace(m.group(0), f"[REDACTED:{rule.rule_id}]")
        for m in CARD_RE.finditer(text):
            if luhn_ok(m.group(0)):
                findings.append(Finding("OUT-009", "LLM02", Severity.HIGH,
                                        "Payment card number (Luhn-valid)", _mask(m.group(0))))
                redacted = redacted.replace(m.group(0), "[REDACTED:CARD]")

        score = _score(findings)
        return Verdict(findings=findings, score=score, blocked=score >= self.block_threshold,
                       sanitized=redacted if self.redact_secrets else None)

    # -- wrapper -------------------------------------------------------------
    def protect(self, llm, prompt: str, refusal: str = "Request blocked by policy.") -> tuple[str, Verdict, Verdict | None]:
        """Run ``llm(prompt) -> str`` behind input and output guards."""
        vin = self.scan_input(prompt)
        if vin.blocked:
            return refusal, vin, None
        reply = llm(vin.sanitized or prompt)
        vout = self.scan_output(reply)
        if vout.blocked and not self.redact_secrets:
            return refusal, vin, vout
        return (vout.sanitized if self.redact_secrets and vout.sanitized is not None else reply), vin, vout


def _mask(value: str) -> str:
    return value if len(value) <= 6 else value[:3] + "…" + value[-2:]
