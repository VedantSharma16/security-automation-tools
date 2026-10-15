"""Detection rule catalogue. Each rule maps to an OWASP LLM Top 10 (2025) risk."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: int          # 1 (weak signal) .. 5 (near-certain attack)
    pattern: re.Pattern
    description: str
    owasp: str = "LLM01"   # LLM01 prompt injection, LLM02 sensitive info disclosure, ...


def _r(id, category, severity, regex, description, owasp="LLM01"):
    return Rule(id, category, severity, re.compile(regex, re.I), description, owasp)


RULES: list[Rule] = [
    _r("PI-001", "instruction_override", 5,
       r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|the)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|guidelines?|directions?|constraints?)\b",
       "Attempts to cancel prior/system instructions."),
    _r("PI-002", "instruction_override", 4,
       r"\b(new|updated|real|actual) (instructions?|task|rules?|system prompt)\b\s*(:|are|is)",
       "Introduces replacement instructions."),
    _r("PI-003", "role_hijack", 4,
       r"\byou are (now|no longer)\b|\bfrom now on,? (you|act|respond|behave)\b|\bact as (an? )?(unrestricted|uncensored|jailbroken|evil|root)\b",
       "Reassigns the model's role or persona."),
    _r("PI-004", "jailbreak", 5,
       r"\b(DAN|do anything now|developer mode|god mode|jailbreak(ed)?)\b|\bno (ethical|safety|content) (restrictions?|filters?|guidelines?)\b|\bwithout (any )?(restrictions?|limitations?|censorship|filters?)\b",
       "Known jailbreak persona or safety-removal phrasing."),
    _r("PI-005", "prompt_exfiltration", 5,
       r"\b(reveal|show|print|repeat|output|display|leak|tell me|what (is|are))\b[^.\n]{0,40}\b(system prompt|initial prompt|hidden (prompt|instructions?)|your (instructions|rules|configuration)|text above)\b",
       "Tries to extract the system prompt.", "LLM07"),
    _r("PI-006", "delimiter_spoofing", 4,
       r"<\|(im_start|im_end|system|endoftext)\|>|\[/?INST\]|<<SYS>>|</?(system|assistant)>|^\s*#{2,}\s*(system|instruction)s?\b|\n\s*(system|assistant)\s*:",
       "Fake chat-template or role delimiters to smuggle privileged turns."),
    _r("PI-007", "exfiltration", 5,
       r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(\{|%7b|data|secret|token|key|prompt|conversation)[^)]*\)",
       "Markdown image with data-carrying query string (zero-click exfiltration).", "LLM02"),
    _r("PI-008", "exfiltration", 4,
       r"\b(send|post|forward|upload|email|exfiltrate|transmit)\b[^.\n]{0,60}\b(conversation|chat history|api[_ -]?keys?|credentials?|secrets?|passwords?|tokens?|system prompt)\b[^.\n]{0,40}\b(to|at)\b[^.\n]{0,20}(https?://|\S+@\S+)",
       "Instructs the model to send sensitive data to an external destination.", "LLM02"),
    _r("PI-009", "indirect_injection", 4,
       r"\b(note|message|instruction)s? (to|for) (the )?(ai|assistant|llm|model|agent|chatbot)\b|\b(ai|assistant|llm) (reading|processing) this\b|\bwhen (the )?(ai|assistant|model) (reads?|sees?|summari[sz]es?)\b",
       "Content addressed to the model, typical of poisoned documents/web pages."),
    _r("PI-010", "tool_abuse", 4,
       r"\b(call|invoke|run|execute|use)\b[^.\n]{0,25}\b(the )?(tool|function|command|shell|terminal|plugin)\b[^.\n]{0,60}\b(rm -rf|curl|wget|nc |netcat|chmod|/etc/passwd|powershell|delete|drop table)\b",
       "Coerces tool use toward destructive or exfiltrating commands.", "LLM06"),
    _r("PI-011", "social_engineering", 2,
       r"\b(this is (a )?(test|emergency|authorized)|i am (the|your) (developer|admin|administrator|owner|creator)|authorized by (openai|anthropic|the admin))\b",
       "Authority/urgency claims used to justify rule-breaking."),
    _r("PI-012", "obfuscation", 3,
       r"\b(base64|rot13|hex|reverse|decode this)\b[^.\n]{0,40}\b(and )?(follow|execute|obey|run|do)\b",
       "Asks the model to decode then obey hidden content."),
    _r("PI-013", "hypothetical_framing", 2,
       r"\b(hypothetically|in a fictional (world|story)|for a (novel|screenplay)|pretend (that )?(you|there))\b[^.\n]{0,80}\b(no rules|no restrictions|anything|bypass|illegal|malware|weapon)\b",
       "Fictional framing wrapped around restricted requests."),
]
