"""Detection rules mapped to OWASP LLM Top 10 (2025) categories."""
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


def _r(id_, category, severity, pattern, description, owasp="LLM01") -> Rule:
    return Rule(id_, category, severity, re.compile(pattern, re.I), description, owasp)


RULES: list[Rule] = [
    _r("INJ-001", "instruction_override", 9,
       r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(all |any |your |the |previous |prior |above |earlier )*(instructions?|rules?|prompts?|guidelines?|directives?|constraints?)",
       "Attempts to override prior instructions"),
    _r("INJ-002", "instruction_override", 7,
       r"\bnew (instructions?|rules?|task|system prompt)\b\s*[:\-]",
       "Injects replacement instructions"),
    _r("INJ-003", "role_hijack", 8,
       r"\b(you are now|from now on,? you|act as|pretend (to be|you are)|roleplay as)\b.{0,60}\b(dan|jailbroken|unrestricted|unfiltered|no (rules|restrictions|limits)|evil|admin|root|developer mode)",
       "Role hijack / jailbreak persona"),
    _r("INJ-004", "role_hijack", 8,
       r"\b(developer|debug|god|sudo|admin) mode\b.{0,20}\b(enabled?|activated?|on)\b",
       "Fake privileged-mode activation"),
    _r("LEAK-001", "prompt_extraction", 8,
       r"\b(reveal|show|print|repeat|output|display|leak|tell me|what (is|are))\b.{0,40}\b(system prompt|initial prompt|hidden (instructions|prompt)|your (instructions|rules|prompt|configuration))",
       "Attempts to extract system prompt", "LLM07"),
    _r("LEAK-002", "prompt_extraction", 6,
       r"\brepeat (everything|the (text|words)) (above|before)\b",
       "Prefix-repeat prompt extraction", "LLM07"),
    _r("DELIM-001", "delimiter_spoofing", 7,
       r"(<\|?(im_start|im_end|system|endoftext)\|?>|\[/?(inst|sys)\]|<<sys>>|^\s*#{2,}\s*(system|instruction)s?\b|</?system>)",
       "Spoofed chat-template / system delimiters"),
    _r("EXFIL-001", "data_exfiltration", 9,
       r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*(\{|%7b|data|secret|token|prompt|key)[^)]*\)",
       "Markdown image URL carrying data (zero-click exfil)", "LLM02"),
    _r("EXFIL-002", "data_exfiltration", 8,
       r"\b(send|post|upload|forward|email|exfiltrate|transmit)\b.{0,50}\b(conversation|chat history|secrets?|credentials?|api[_ -]?keys?|passwords?|tokens?|system prompt)\b.{0,50}\b(to|at)\b.{0,30}(https?://|\S+@\S+)",
       "Instructs data exfiltration to external destination", "LLM02"),
    _r("AGENT-001", "tool_abuse", 9,
       r"\b(run|execute|call|invoke)\b.{0,30}\b(rm -rf|curl [^|]*\|\s*(ba)?sh|wget [^|]*\|\s*(ba)?sh|powershell -enc|nc -e|chmod 777|/etc/passwd|/etc/shadow)",
       "Dangerous command execution via agent tools", "LLM06"),
    _r("AGENT-002", "tool_abuse", 7,
       r"\b(without|don'?t|do not)\b.{0,20}\b(ask|asking|confirm|confirmation|telling|notify|inform)\b.{0,20}\b(user|human|me)\b",
       "Suppresses human-in-the-loop confirmation", "LLM06"),
    _r("INDIRECT-001", "indirect_injection", 6,
       r"\b(attention|note|important)\b.{0,15}\b(ai|assistant|llm|model|agent|chatbot)\b.{0,10}[:,!]",
       "Text addressed to the AI assistant embedded in content"),
    _r("INDIRECT-002", "indirect_injection", 6,
       r"\b(when|if) (the )?(ai|assistant|llm|model|agent)\b.{0,30}\b(reads?|summari[sz]es?|processes?|sees?)\b.{0,30}\b(this|these)\b",
       "Conditional trigger aimed at an AI reader"),
    _r("JB-001", "jailbreak", 5,
       r"\b(hypothetically|for (educational|research|fictional) purposes|in a fictional (world|story)|purely theoretical)\b.{0,80}\b(bypass|exploit|malware|ransomware|weapon|synthesi[sz]e)",
       "Fictional / hypothetical framing to extract harmful content"),
    _r("JB-002", "jailbreak", 6,
       r"\b(do anything now|dan\b|no ethical|without (any )?(censorship|filters?|restrictions?|safety))",
       "Known jailbreak vocabulary"),
]

# Obfuscation signals (not regex-driven): (id, severity, description)
OBFUSCATION_HIDDEN = ("OBF-001", 5, "Zero-width / bidi control characters present")
OBFUSCATION_ENCODED = ("OBF-002", 4, "Detection only fired on a decoded/obfuscated view")
