"""Detection rules. Each rule is a regex over normalised text."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: Severity
    description: str
    pattern: re.Pattern

    @classmethod
    def make(cls, rule_id, category, severity, description, regex) -> "Rule":
        return cls(rule_id, category, severity, description, re.compile(regex, re.I))


# --- Input (prompt injection) rules; run on normalised text -----------------
INPUT_RULES: list[Rule] = [
    Rule.make("PI-001", "LLM01", Severity.HIGH, "Instruction override",
              r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|prior|above|earlier|all|any|your|the)\b.{0,30}\b(instructions?|rules?|prompts?|guidelines?|directives?|constraints?)\b"),
    Rule.make("PI-002", "LLM01", Severity.HIGH, "System prompt extraction attempt",
              r"\b(reveal|show|print|repeat|output|leak|display|tell me)\b.{0,40}\b(system prompt|initial prompt|hidden prompt|your instructions|your prompt|original instructions)\b"),
    Rule.make("PI-003", "LLM01", Severity.HIGH, "Persona / jailbreak mode switch",
              r"\b(you are now|act as|pretend to be|from now on you are|enter)\b.{0,40}\b(dan|developer mode|jailbreak|unrestricted|no restrictions|without (any )?(restrictions|filters|limits))\b"),
    Rule.make("PI-004", "LLM01", Severity.MEDIUM, "Fake role / delimiter injection",
              r"(^|\n|\s)(system|assistant)\s*:\s|<\|?(im_start|im_end|system|endoftext)\|?>|\[/?inst\]|###\s*(system|instruction)"),
    Rule.make("PI-005", "LLM01", Severity.MEDIUM, "Safety-filter evasion framing",
              r"\b(hypothetically|for educational purposes|in a fictional story|roleplay)\b.{0,60}\b(bypass|disable|turn off)\b.{0,30}\b(safety|filter|guardrail|moderation)"),
    Rule.make("PI-006", "LLM06", Severity.HIGH, "Tool / agent abuse (exfiltration or destructive command)",
              r"\b(send|post|upload|forward|email|exfiltrate)\b.{0,60}\b(to|at)\b.{0,10}(https?://|[\w.-]+@[\w.-]+)|\b(rm\s+-rf|curl\s+[^|]+\|\s*(ba)?sh|drop\s+table|cat\s+/etc/(passwd|shadow))"),
    Rule.make("PI-007", "LLM01", Severity.MEDIUM, "Indirect injection aimed at the model inside data",
              r"\b(note to (the )?(ai|assistant|model|llm)|attention (ai|assistant)|if you are an? (ai|llm|language model)|when (the )?(ai|assistant) reads this)\b"),
    Rule.make("PI-008", "LLM01", Severity.MEDIUM, "Instruction obfuscation via encoding request",
              r"\b(decode|base64|rot13|hex)\b.{0,30}\b(and|then)\b.{0,20}\b(execute|run|follow|obey)\b"),
]

# --- Output rules; run on raw text -----------------------------------------
SECRET_PATTERNS: list[Rule] = [
    Rule.make("OUT-001", "LLM02", Severity.CRITICAL, "AWS access key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    Rule.make("OUT-002", "LLM02", Severity.CRITICAL, "Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    Rule.make("OUT-003", "LLM02", Severity.HIGH, "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    Rule.make("OUT-004", "LLM02", Severity.HIGH, "API key-style token", r"\b(sk|pk|api|key)[-_][A-Za-z0-9_-]{20,}\b"),
    Rule.make("OUT-005", "LLM02", Severity.HIGH, "JSON Web Token", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    Rule.make("OUT-006", "LLM02", Severity.MEDIUM, "Password assignment", r"\b(password|passwd|pwd|secret)\s*[:=]\s*\S{6,}"),
    Rule.make("OUT-007", "LLM02", Severity.MEDIUM, "US SSN", r"\b\d{3}-\d{2}-\d{4}\b"),
    Rule.make("OUT-008", "LLM02", Severity.MEDIUM, "Email address", r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
]
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
