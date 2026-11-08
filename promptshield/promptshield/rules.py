"""Detection rules. Each maps to an OWASP LLM Top 10 (2025) category."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: int  # 1 (low) .. 10 (critical)
    pattern: re.Pattern
    description: str
    owasp: str = "LLM01"


def _r(id, category, severity, pattern, description, owasp="LLM01"):
    return Rule(id, category, severity, re.compile(pattern, re.I), description, owasp)


RULES: list[Rule] = [
    _r("PI-001", "instruction_override", 9,
       r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|system)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|guidelines?|directives?|context)\b",
       "Attempts to cancel prior instructions"),
    _r("PI-002", "instruction_override", 7,
       r"\b(new|updated|real|actual) (instructions?|task|rules?)\s*(are|is|:)",
       "Declares replacement instructions"),
    _r("PI-003", "role_hijack", 7,
       r"\byou are (now|no longer|actually)\b|\bact as (if you (are|were)|an? (unrestricted|unfiltered|jailbroken))|\bpretend (to be|you are)\b",
       "Reassigns the model's role/persona"),
    _r("PI-004", "jailbreak", 8,
       r"\b(DAN|do anything now|(enable|activate|enter|switch to) developer mode|jailbreak(ed)?|no (restrictions|limitations|filters|guardrails)|without (any )?(restrictions|censorship|safety))\b",
       "Known jailbreak framing"),
    _r("PI-005", "prompt_leak", 8,
       r"\b(reveal|show|print|repeat|output|display|leak|tell me)\b[^.\n]{0,40}\b(system prompt|initial prompt|hidden (prompt|instructions)|your (instructions|rules|configuration))\b",
       "Attempts to extract the system prompt", "LLM07"),
    _r("PI-006", "delimiter_spoof", 7,
       r"(<\|?(im_start|im_end|system|endoftext)\|?>|\[/?(INST|SYS)\]|<</?SYS>>|^#{2,}\s*system\b|^\s*(system|assistant)\s*:)",
       "Spoofs chat-template or role delimiters"),
    _r("PI-007", "exfiltration", 9,
       r"(!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*(=|%3d)[^)]*\)|\b(send|post|upload|forward|exfiltrate|email)\b[^.\n]{0,40}\b(conversation|history|data|secrets?|credentials?|keys?|tokens?|passwords?|prompt|context|files?)\b[^.\n]{0,30}\b(to|at)\b[^.\n]{0,20}(https?://|[\w.+-]+@[\w-]+\.[\w.]+))",
       "Data exfiltration via URL/markdown image/email", "LLM02"),
    _r("PI-008", "tool_abuse", 9,
       r"\b(call|invoke|run|execute|use)\b[^.\n]{0,25}\b(tool|function|command|shell|bash|powershell|code)\b[^.\n]{0,40}\b(rm -rf|curl|wget|nc |netcat|chmod|/etc/passwd|delete|drop table)\b",
       "Coerces tool/agent into destructive or network actions", "LLM06"),
    _r("PI-009", "indirect_injection", 6,
       r"\b(attention|note|important|instruction)s? (to|for) (the )?(ai|assistant|llm|model|agent|chatbot)\b|\bwhen (the )?(ai|assistant|llm|model) (reads|sees|processes) this\b",
       "Addresses the AI directly inside data content"),
    _r("PI-010", "secrecy", 5,
       r"\b(do not|don't|never) (tell|inform|mention|reveal|disclose)[^.\n]{0,30}\b(user|human|anyone|operator)\b",
       "Instructs concealment from the user"),
    _r("PI-011", "encoding_evasion", 4,
       r"\b(decode|base64|rot13|hex)\b[^.\n]{0,30}\b(and|then)\b[^.\n]{0,20}\b(follow|execute|obey|run|apply)\b",
       "Asks the model to decode then obey hidden content"),
]
