"""Detection rules. Severity weights: 1 low, 3 medium, 5 high."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: int
    description: str
    pattern: re.Pattern


def _r(id_: str, cat: str, sev: int, desc: str, pat: str) -> Rule:
    return Rule(id_, cat, sev, desc, re.compile(pat, re.I))


RULES: list[Rule] = [
    _r("PI-001", "instruction_override", 5, "Tells the model to ignore prior instructions",
       r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|the)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|guidelines?|directives?|context)\b"),
    _r("PI-002", "instruction_override", 3, "New-instructions preamble",
       r"\b(new|updated|real|actual|revised)\s+(instructions?|task|system prompt|directive)s?\s*[:\-]"),
    _r("PI-003", "role_hijack", 4, "Attempts to reassign the model's role",
       r"\b(you are now|from now on,? you|you (must|will|should) act as|pretend (to be|you are)|behave as|your new role)\b"),
    _r("PI-004", "jailbreak", 5, "Known jailbreak persona / mode",
       r"\b(DAN|do anything now|developer mode|no (restrictions|filters|limitations)|unfiltered mode|without (any )?(restrictions|censorship))\b"),
    _r("PI-013", "jailbreak", 1, "Mentions jailbreaking (weak signal)", r"\bjailbreak(ed|ing|s)?\b"),
    _r("PI-005", "prompt_exfiltration", 5, "Requests disclosure of the system prompt",
       r"\b(reveal|show|print|repeat|output|leak|display|tell me)\b[^.\n]{0,40}\b(system prompt|initial prompt|hidden instructions?|your instructions|your prompt|developer message)\b"),
    _r("PI-006", "delimiter_injection", 4, "Fake chat/system delimiters",
       r"(<\|?(im_start|im_end|system|assistant|endoftext)\|?>|\[/?INST\]|<<\s*SYS\s*>>|^\s*#{2,}\s*(system|instruction)s?\b|^\s*(system|assistant)\s*:)"),
    _r("PI-007", "data_exfiltration", 5, "Markdown image/link that can leak data via URL parameters",
       r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*=\s*(\{|<|%7B|\$)[^)]*\)"),
    _r("PI-008", "data_exfiltration", 4, "Instructs sending data to an external destination",
       r"\b(send|post|upload|forward|exfiltrate|transmit|email)\b[^.\n]{0,40}\b(conversation|chat|history|credentials?|passwords?|secrets?|api keys?|tokens?|context|memory|system prompt|private|confidential)\b[^.\n]{0,40}\b(to|at)\b[^.\n]{0,30}(https?://|[\w.+-]+@[\w-]+\.[\w.]+)"),
    _r("PI-009", "tool_abuse", 4, "Directs the model to invoke tools/commands covertly",
       r"\b(call|invoke|execute|run)\b[^.\n]{0,30}\b(the )?(tool|function|command|shell|code|script)\b[^.\n]{0,60}\b(without|silently|do not (tell|inform|mention)|secretly)\b"),
    _r("PI-010", "concealment", 3, "Asks the model to hide its behaviour from the user",
       r"\b(do not|don't|never)\b[^.\n]{0,20}\b(tell|inform|mention|reveal|alert|notify)\b[^.\n]{0,20}\b(the )?(user|human|operator)\b"),
    _r("PI-011", "authority_spoof", 2, "Claims special authority over the model",
       r"\b(i am|this is|message from)\b[^.\n]{0,25}\b(your (developer|creator|admin(istrator)?)|the (developer|system administrator)|anthropic|openai)\b"),
    _r("PI-012", "instruction_override", 3, "Targets the assistant directly from within data",
       r"\b(attention|note to|important[:!]?)\s*(ai|assistant|llm|model|agent|chatgpt|claude)\b"),
]
