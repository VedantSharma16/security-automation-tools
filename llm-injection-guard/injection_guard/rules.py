"""Detection rules. Each rule maps to a category and an ATLAS / OWASP-LLM reference."""

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
    reference: str


def _r(id, category, severity, pattern, description, reference="OWASP LLM01 / MITRE ATLAS AML.T0051"):
    return Rule(id, category, severity, re.compile(pattern, re.I), description, reference)


RULES: list[Rule] = [
    _r("PI-001", "instruction_override", 8,
       r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your)\b[^.\n]{0,30}\b(instructions?|rules?|prompts?|guidelines?|directives?|constraints?)\b",
       "Attempts to cancel the system prompt or earlier instructions."),
    _r("PI-002", "instruction_override", 6,
       r"\b(new|updated|real|actual) (instructions?|rules?|task)\b\s*(:|are|is)",
       "Declares replacement instructions."),
    _r("PI-003", "role_hijack", 7,
       r"\b(you are now|from now on,? you|act as|pretend (to be|you are)|roleplay as|simulate being)\b[^.\n]{0,60}\b(dan|jailbroken|unrestricted|unfiltered|no (restrictions|limits|rules)|evil|developer mode)\b",
       "Persona/jailbreak roleplay to escape policy."),
    _r("PI-004", "role_hijack", 7,
       r"\b(developer|debug|god|sudo|admin(istrator)?) mode\b[^.\n]{0,30}\b(enabled|activated|on|unlocked)\b",
       "Fake privileged-mode activation."),
    _r("PI-005", "prompt_extraction", 8,
       r"\b(reveal|show|print|repeat|output|display|leak|tell me|what (is|are))\b[^.\n]{0,40}\b(system prompt|system message|initial (prompt|instructions)|hidden (prompt|instructions)|your (instructions|rules|prompt))\b",
       "Tries to exfiltrate the system prompt.", "OWASP LLM07 / AML.T0051"),
    _r("PI-006", "fake_delimiter", 7,
       r"(<\|?(im_start|im_end|system|endoftext)\|?>|\[/?(INST|SYS)\]|<<SYS>>|^\s*#{2,}\s*(system|instruction)s?\b|\bend of (system )?(prompt|instructions)\b)",
       "Spoofs chat-template or prompt boundary tokens."),
    _r("PI-007", "fake_authority", 5,
       r"\b(message|note|notice|update) (from|by) (the )?(system|developer|administrator|openai|anthropic|security team)\b|\bauthorized by (the )?(system|developer|admin)",
       "Impersonates a trusted authority."),
    _r("EX-001", "data_exfiltration", 9,
       r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*(\{|%7b|data|secret|token|key|prompt|chat)[^)\s]*\)",
       "Markdown image beacon that can leak data via URL parameters.", "OWASP LLM02 / AML.T0057"),
    _r("EX-002", "data_exfiltration", 8,
       r"\b(send|post|forward|upload|email|exfiltrate|transmit)\b[^.\n]{0,60}\b(conversation|chat history|api[ _-]?keys?|credentials?|passwords?|secrets?|tokens?|system prompt|private data|environment variables)\b[^.\n]{0,60}\b(to|at)\b[^.\n]{0,30}(https?://|[\w.-]+@[\w.-]+|\b\d{1,3}(\.\d{1,3}){3}\b)",
       "Instructs the model to send sensitive data to an external destination.", "OWASP LLM02 / AML.T0057"),
    _r("TA-001", "tool_abuse", 8,
       r"\b(call|invoke|run|execute|use)\b[^.\n]{0,30}\b(tool|function|command|shell|terminal|bash|powershell)\b[^.\n]{0,60}\b(rm -rf|curl|wget|nc |netcat|chmod|/etc/passwd|base64 -d|delete|drop table)",
       "Coerces the agent into running destructive or exfiltrating tools.", "OWASP LLM06 / AML.T0053"),
    _r("TA-002", "tool_abuse", 6,
       r"\b(do not|don't|never|without)\b[^.\n]{0,20}\b(tell|inform|notify|alert|ask|confirm with)\b[^.\n]{0,20}\b(the )?(user|human|operator)\b",
       "Asks the agent to hide actions from the user (confirmation bypass).", "OWASP LLM06"),
    _r("IN-001", "indirect_injection", 6,
       r"\b(when|if) (an? )?(ai|llm|assistant|language model|chatbot|agent)\b[^.\n]{0,40}\b(read|reads|summari[sz]e|process|see|sees)\b[^.\n]{0,40}\b(this|the following)\b",
       "Content addressed to an AI that will read it (typical of poisoned documents).", "OWASP LLM01 (indirect)"),
    _r("IN-002", "indirect_injection", 6,
       r"\b(attention|note to|instructions? for|dear)\s+(ai|llm|assistant|language model|agent|chatbot)\b",
       "Directly addresses an AI agent from inside retrieved content.", "OWASP LLM01 (indirect)"),
    _r("JB-001", "jailbreak", 5,
       r"\b(hypothetically|for (a )?(fiction|story|educational purposes)|in a fictional world)\b[^.\n]{0,80}\b(how to|steps to|instructions? (for|to))\b[^.\n]{0,40}\b(malware|ransomware|bomb|weapon|exploit|keylogger|phishing)\b",
       "Fictional/hypothetical framing wrapped around harmful requests.", "OWASP LLM01 / AML.T0054"),
    _r("OB-001", "obfuscation", 4,
       r"\b(decode|decrypt|deobfuscate)\b[^.\n]{0,30}\b(and|then)\b[^.\n]{0,20}\b(follow|execute|run|obey|apply)\b",
       "Asks the model to decode and then obey hidden instructions."),
]
