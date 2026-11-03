"""Detection rules mapped to the OWASP Top 10 for LLM Applications (2025)
and MITRE ATLAS technique IDs."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str       # OWASP LLM category
    atlas: str          # MITRE ATLAS technique
    severity: int       # 1-10
    pattern: re.Pattern
    description: str


def _r(id_, name, category, atlas, sev, pat, desc) -> Rule:
    return Rule(id_, name, category, atlas, sev, re.compile(pat, re.I | re.S), desc)


LLM01 = "LLM01 Prompt Injection"
LLM02 = "LLM02 Sensitive Information Disclosure"
LLM07 = "LLM07 System Prompt Leakage"
LLM06 = "LLM06 Excessive Agency"

RULES: list[Rule] = [
    _r("PI-001", "Instruction override", LLM01, "AML.T0051.000", 8,
       r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your)\b[^.\n]{0,30}\b(instructions?|rules?|prompts?|guidelines?|directives?|constraints?)\b",
       "Attempts to cancel the developer's instructions."),
    _r("PI-002", "Role / persona hijack", LLM01, "AML.T0054", 8,
       r"\b(you are now|from now on,? you|act as|pretend (to be|you are)|roleplay as|simulate)\b[^.\n]{0,60}\b(dan|developer mode|jailbroken|unrestricted|no (rules|restrictions|filters)|evil|uncensored)\b",
       "Reassigns the model to an unrestricted persona."),
    _r("PI-003", "Known jailbreak phrase", LLM01, "AML.T0054", 7,
       r"\b(do anything now|developer mode (enabled|on)|jailbreak(ed)? mode|without (any )?(ethical|safety) (guidelines|restrictions|filters)|no longer bound by)\b",
       "Matches well-known jailbreak templates."),
    _r("PI-004", "Fake system/role delimiter", LLM01, "AML.T0051.001", 7,
       r"(^|\n)\s*(#{2,}\s*)?(\[?/?(system|assistant)\]?\s*:|<\|?(im_start|im_end|system|endoftext)\|?>|<</?SYS>>|\[/?INST\])",
       "Injects chat-template tokens to forge a privileged message."),
    _r("PI-005", "Indirect injection addressed to AI", LLM01, "AML.T0051.001", 8,
       r"\b(note|message|instruction)s? (to|for) (the )?(ai|assistant|llm|model|agent|chatbot)\b|\bif you are an? (ai|llm|language model|assistant)\b|\bwhen (the )?(ai|assistant|model) (reads|sees|processes)\b",
       "Content aimed at an AI that processes it (RAG/web/email poisoning)."),
    _r("SP-001", "System prompt extraction", LLM07, "AML.T0056", 7,
       r"\b(reveal|show|print|repeat|output|display|leak|tell me|what (is|are))\b[^.\n]{0,40}\b(system prompt|initial prompt|hidden (prompt|instructions)|your (instructions|rules|configuration)|text above)\b|repeat (everything|the words|all text) above",
       "Tries to exfiltrate the system prompt."),
    _r("EX-001", "Exfiltration via markdown/URL", LLM02, "AML.T0057", 8,
       r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*(\{|%7B|data|secret|token|key|prompt)[^)\s]*\)|\b(send|post|forward|email|upload|exfiltrate)\b[^.\n]{0,50}\b(conversation|chat history|secrets?|credentials?|api[_ -]?keys?|passwords?|tokens?)\b[^.\n]{0,40}\b(to|at|via)\b",
       "Smuggles data out through rendered links/images or tool calls."),
    _r("AG-001", "Dangerous tool / command request", LLM06, "AML.T0053", 9,
       r"\b(rm\s+-rf|curl[^|\n]{0,80}\|\s*(ba)?sh|wget[^|\n]{0,80}\|\s*(ba)?sh|chmod\s+777|nc\s+-e|/etc/(passwd|shadow)|powershell\s+-enc|DROP\s+TABLE|;\s*--)",
       "Requests destructive or remote-code execution actions."),
    _r("AG-002", "Autonomous action without confirmation", LLM06, "AML.T0053", 5,
       r"\b(do not|don't|without)\b[^.\n]{0,20}\b(ask|confirm|verif(y|ication)|tell the user|notify)\b|\bsilently\b[^.\n]{0,30}\b(run|execute|send|delete|call)\b",
       "Tries to suppress human-in-the-loop checks."),
]

# Output/secret-leak rules (used on text containing credentials, e.g. model output)
SECRET_RULES: list[Rule] = [
    _r("SE-001", "AWS access key", LLM02, "AML.T0057", 9, r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "AWS access key ID."),
    _r("SE-002", "Private key block", LLM02, "AML.T0057", 10, r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "PEM private key."),
    _r("SE-003", "Generic API token", LLM02, "AML.T0057", 8,
       r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b", "Provider API token."),
    _r("SE-004", "JWT", LLM02, "AML.T0057", 6, r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "JSON Web Token."),
    _r("SE-005", "Credential assignment", LLM02, "AML.T0057", 7,
       r"\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*['\"]?[^\s'\"]{8,}", "Hard-coded credential."),
    _r("SE-006", "US SSN", LLM02, "AML.T0057", 7, r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", "Social Security number."),
]
