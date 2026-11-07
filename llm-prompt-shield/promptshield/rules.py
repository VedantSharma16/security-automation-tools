"""Detection rules. Each rule is a compiled regex applied to normalised text."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Severity as S

I = re.IGNORECASE


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: S
    description: str
    pattern: re.Pattern
    owasp: str
    directions: tuple[str, ...] = ("input", "output")


def _r(id, cat, sev, desc, pat, owasp, directions=("input", "output")):
    return Rule(id, cat, sev, desc, re.compile(pat, I), owasp, directions)


LLM01, LLM02, LLM06 = "LLM01:Prompt Injection", "LLM02:Insecure Output Handling", "LLM06:Sensitive Info Disclosure"

RULES: list[Rule] = [
    # --- prompt injection -------------------------------------------------
    _r("PI-001", "prompt_injection", S.HIGH, "Instruction override",
       r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|system)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|guidelines?|directives?|context)\b",
       LLM01, ("input",)),
    _r("PI-002", "prompt_injection", S.HIGH, "System prompt extraction attempt",
       r"\b(reveal|show|print|repeat|output|display|leak|tell me)\b[^.\n]{0,40}\b(system|initial|hidden|original|secret)\b[^.\n]{0,15}\b(prompt|instructions?|message)\b",
       LLM06, ("input",)),
    _r("PI-003", "prompt_injection", S.HIGH, "Chat-template / delimiter injection",
       r"(<\|(im_start|im_end|system|endoftext)\|>|\[/?INST\]|<</?SYS>>|^\s*#{2,}\s*(system|instruction)s?\b|</?(system|assistant)>)",
       LLM01, ("input",)),
    _r("PI-004", "prompt_injection", S.MEDIUM, "Fake authority / new-instructions marker",
       r"\b(new|updated|real|actual) (instructions?|task|directive)s?\s*:|\bimportant\s*:\s*(you must|ignore|instead)|\b(admin|developer|system) (override|mode|message)\b",
       LLM01, ("input",)),
    # --- jailbreak --------------------------------------------------------
    _r("JB-001", "jailbreak", S.HIGH, "Persona jailbreak (DAN-style)",
       r"\b(do anything now|\b(you are|act as|called|named|as) (?-i:DAN)\b|jailbroken|developer mode (enabled|on)|no (ethical|moral|safety) (guidelines|restrictions|filters))\b",
       LLM01, ("input",)),
    _r("JB-002", "jailbreak", S.MEDIUM, "Role-play restriction removal",
       r"\b(you are|act as|pretend (to be|you are)|roleplay as)\b[^.\n]{0,60}\b(without|no|free (of|from)|unrestricted|unfiltered|uncensored)\b[^.\n]{0,20}\b(restrictions?|limits?|filters?|rules|censorship|ethics)\b",
       LLM01, ("input",)),
    # --- exfiltration / insecure output ----------------------------------
    _r("EX-001", "exfiltration", S.HIGH, "Markdown image/link beacon with data in URL",
       r"!?\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]*(data|q|secret|token|key|prompt|d)=[^)\s]{6,}\)",
       LLM02),
    _r("EX-002", "exfiltration", S.CRITICAL, "Download-and-execute shell pattern",
       r"\b(curl|wget)\b[^\n|]{0,120}\|\s*(sudo\s+)?(ba|z|da)?sh\b|powershell[^\n]{0,40}-enc(odedcommand)?\b|\bIEX\s*\(\s*New-Object\s+Net\.WebClient",
       LLM02, ("output",)),
    _r("EX-003", "exfiltration", S.MEDIUM, "Script injection in output",
       r"<script\b|javascript:\s*\w|\bon(error|load)\s*=",
       LLM02, ("output",)),
    # --- secrets ----------------------------------------------------------
    _r("SE-001", "secret", S.CRITICAL, "AWS access key ID", r"(?-i:\b(AKIA|ASIA)[0-9A-Z]{16}\b)", LLM06),
    _r("SE-002", "secret", S.CRITICAL, "Private key block", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY", LLM06),
    _r("SE-003", "secret", S.CRITICAL, "GitHub token", r"(?-i:\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,})", LLM06),
    _r("SE-004", "secret", S.HIGH, "Generic API key/secret assignment",
       r"\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{16,}", LLM06),
    _r("SE-005", "secret", S.CRITICAL, "Anthropic/OpenAI style API key", r"(?-i:\bsk-(ant-)?[A-Za-z0-9_\-]{20,})", LLM06),
    # --- PII --------------------------------------------------------------
    _r("PII-001", "pii", S.MEDIUM, "US SSN", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", LLM06),
    _r("PII-002", "pii", S.LOW, "Email address", r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b", LLM06),
]
