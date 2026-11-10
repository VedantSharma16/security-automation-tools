"""Detection rules for indirect prompt injection (OWASP LLM01).

Each rule has an id, category, severity weight (1-10), a compiled regex and a
short rationale. Rules are deliberately explainable: every finding points to the
exact matched span and the reason it matters.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: int
    pattern: re.Pattern
    description: str


def _r(id_: str, cat: str, sev: int, pat: str, desc: str) -> Rule:
    return Rule(id_, cat, sev, re.compile(pat, re.I | re.S), desc)


RULES: list[Rule] = [
    _r("PI-001", "instruction-override", 9,
       r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|system|your)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|guidelines?|directives?|context)\b",
       "Attempts to cancel the model's existing instructions."),
    _r("PI-002", "role-hijack", 7,
       r"\b(you are now|from now on,? you|act as|pretend (to be|you are)|new persona|enter (developer|dan|jailbreak) mode)\b",
       "Tries to reassign the model's role or persona."),
    _r("PI-003", "prompt-exfiltration", 8,
       r"\b(reveal|print|show|repeat|output|leak|disclose|tell me)\b[^.\n]{0,40}\b(system prompt|hidden prompt|initial instructions|your instructions|developer message|secret key|api key)\b",
       "Tries to extract the system prompt or secrets."),
    _r("PI-004", "fake-delimiters", 7,
       r"(<\|?(im_start|im_end|system|endoftext)\|?>|\[/?INST\]|<</?SYS>>|^\s*(system|assistant)\s*:\s)",
       "Injects chat-template or role delimiters to spoof a privileged message."),
    _r("PI-005", "data-exfiltration", 9,
       r"(!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*(\{|%7B|data|secret|token|q|c)=[^)]*\)|\b(send|post|forward|upload|exfiltrate|email)\b[^.\n]{0,60}\b(conversation|chat history|user data|credentials|passwords?|secrets?|tokens?)\b[^.\n]{0,40}\b(to|at)\b[^.\n]{0,10}(https?://|\S+@\S+))",
       "Markdown-image or explicit instruction to ship data to an external endpoint."),
    _r("PI-006", "tool-abuse", 8,
       r"\b(call|invoke|execute|run|use)\b[^.\n]{0,30}\b(the )?(tool|function|shell|command|terminal|bash|powershell|curl|wget)\b[^.\n]{0,60}(rm -rf|curl|wget|nc |/bin/(ba)?sh|powershell|chmod|sudo|\|\s*sh)",
       "Instructs the agent to invoke tools/commands with dangerous payloads."),
    _r("PI-007", "audience-targeting", 5,
       r"\b(note to (the )?(ai|assistant|llm|model|agent)|attention (ai|assistant|llm)|(ai|llm) (assistant )?(reading|processing) this|if you are an? (ai|llm|language model))\b",
       "Text addressed directly at an AI reader, rarely legitimate in a document."),
    _r("PI-008", "secrecy", 6,
       r"\b(do not|don't|never)\b[^.\n]{0,30}\b(tell|inform|mention|alert|notify|reveal to)\b[^.\n]{0,30}\b(the )?(user|human|operator)\b",
       "Asks the model to conceal behaviour from the user."),
    _r("PI-009", "output-manipulation", 6,
       r"\b(respond|reply|answer|output)\b[^.\n]{0,20}\b(only|exactly|always|just)\b[^.\n]{0,20}(with|:|\")",
       "Forces a fixed output, a common way to hijack answers."),
    _r("PI-010", "authority-claim", 5,
       r"\b(this (message|instruction|document) (is|comes) from (the )?(system|admin|administrator|developer|openai|anthropic)|authorized by (the )?(admin|system|developer)|priority override|urgent system (notice|update))\b",
       "Claims elevated authority to legitimise injected instructions."),
]
