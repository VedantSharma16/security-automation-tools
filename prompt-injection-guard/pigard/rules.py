"""Detection rules mapped to OWASP LLM Top 10 (2025) categories."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    owasp: str
    severity: int  # 1-10
    pattern: re.Pattern
    description: str


def _r(id, category, owasp, sev, pat, desc):
    return Rule(id, category, owasp, sev, re.compile(pat, re.I), desc)


RULES: list[Rule] = [
    _r("PI-001", "instruction_override", "LLM01", 8,
       r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|prompts?|rules?|guidelines?|directives?)\b",
       "Attempts to cancel the system prompt / prior instructions"),
    _r("PI-002", "role_hijack", "LLM01", 6,
       r"\b(you are now|from now on you are|act as|pretend (to be|you are)|roleplay as)\b.{0,60}\b(dan|unrestricted|jailbroken|no (rules|restrictions|limits)|evil|developer mode)\b",
       "Persona swap to remove safety behaviour"),
    _r("PI-003", "jailbreak", "LLM01", 7,
       r"\b(do anything now|developer mode (enabled|on)|jailbreak(ed)?|without (any )?(restrictions|filters|censorship|safety))\b",
       "Known jailbreak vocabulary"),
    _r("PI-004", "prompt_extraction", "LLM07", 7,
       r"\b(reveal|show|print|repeat|output|leak|tell me|display)\b.{0,40}\b(system prompt|initial prompt|hidden (prompt|instructions)|your (instructions|rules|configuration))\b",
       "Tries to exfiltrate the system prompt"),
    _r("PI-005", "delimiter_injection", "LLM01", 6,
       r"(</?(system|assistant|instructions?)>|\[/?(INST|SYS)\]|<\|(im_start|im_end|system)\|>|^\s*#{2,}\s*system\b)",
       "Fake chat-template or role delimiters"),
    _r("PI-006", "data_exfiltration", "LLM02", 9,
       r"(!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*=|\b(send|post|forward|upload|exfiltrate)\b.{0,50}\b(to|at)\b.{0,10}https?://)",
       "Markdown-image or instruction-driven exfiltration channel"),
    _r("PI-007", "tool_abuse", "LLM06", 9,
       r"\b(call|invoke|run|execute|use)\b.{0,30}\b(tool|function|shell|command|curl|wget|rm -rf|powershell|bash)\b.{0,60}\b(without|silently|quietly|don'?t (tell|ask|notify))\b",
       "Covert tool/command invocation request"),
    _r("PI-008", "indirect_instruction", "LLM01", 7,
       r"\b(note to (the )?(ai|assistant|model|llm)|attention (ai|assistant|llm)|(ai|assistant|llm) (agents?)?,? (must|should|please) (now )?)\b",
       "Content addressed to the model embedded in data (indirect injection)"),
    _r("PI-009", "secrecy", "LLM01", 5,
       r"\b(do not|don'?t|never)\b.{0,20}\b(tell|inform|mention|reveal|alert)\b.{0,20}\b(the )?(user|human|operator)\b",
       "Instructs the model to hide actions from the user"),
]
