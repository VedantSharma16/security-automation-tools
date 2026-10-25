"""Detection rules, each mapped to an OWASP LLM Top 10 (2025) category."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: int  # 1 (weak signal) .. 10 (near-certain attack)
    description: str
    pattern: re.Pattern[str]


def _r(id: str, category: str, severity: int, description: str, pattern: str) -> Rule:
    return Rule(id, category, severity, description, re.compile(pattern, re.I))


_QUALIFIER = r"(?:\w+\s+){0,3}"

RULES: tuple[Rule, ...] = (
    _r("PI-001", "instruction_override", 9,
       "Tells the model to ignore or discard prior instructions",
       rf"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|every\s+)?(?:of\s+)?(?:the\s+|your\s+|my\s+)?"
       rf"{_QUALIFIER}(?:instructions?|rules?|guidelines?|prompts?|directions?|constraints?|restrictions?)"),
    _r("PI-002", "instruction_override", 7,
       "Attempts to reset the conversation or declare a new task",
       r"\b(?:new instructions?|from now on|starting now|your new (?:task|role|job) is)\b"),
    _r("PI-003", "prompt_leak", 9,
       "Requests the system prompt or hidden instructions",
       rf"\b(?:reveal|show|print|repeat|output|display|leak|tell me|what (?:is|are))\b.{{0,40}}"
       rf"\b(?:system|initial|hidden|original|secret)\s+(?:prompt|instructions?|message)"),
    _r("PI-004", "prompt_leak", 6,
       "Asks the model to repeat everything above or verbatim",
       r"\b(?:repeat|print|output)\b.{0,20}\b(?:everything|all|text)\b.{0,20}\b(?:above|before|verbatim)\b"),
    _r("JB-001", "jailbreak", 8,
       "Known persona jailbreak (DAN / developer mode / no-restrictions persona)",
       r"\b(?:DAN|do anything now|jailbreak(?:ed)?|god mode|unfiltered mode)\b|"
       r"\b(?:enable|activate|enter|switch to|turn on)\s+(?:the\s+)?developer mode\b"),
    _r("JB-002", "jailbreak", 7,
       "Role-play framing that strips safety behaviour",
       r"\b(?:pretend|act|behave|roleplay|role-play)\b.{0,40}\b(?:no|without|free (?:from|of))\s+(?:\w+\s+)?"
       r"(?:restrictions?|filters?|limitations?|rules|ethics|guidelines|censorship)"),
    _r("JB-003", "jailbreak", 6,
       "Claims that safety rules do not apply (hypothetical / fictional / authorised bypass)",
       r"\b(?:you (?:are|have) (?:now )?(?:free|no longer bound)|no longer (?:bound|restricted)|"
       r"without any (?:restrictions|limitations|filters))\b"),
    _r("RP-001", "role_spoofing", 8,
       "Fake system/developer message markers embedded in user content",
       r"(?:^|\n|\s)(?:\[/?(?:system|inst)\]|<\|?(?:system|im_start|im_end)\|?>|###\s*(?:system|instruction)s?\b|"
       r"(?:system|developer|admin)\s*(?:message|override|note)\s*:)"),
    _r("RP-002", "role_spoofing", 6,
       "Claims elevated authority (developer, admin, OpenAI/Anthropic staff)",
       r"\b(?:i am|i'm|this is)\s+(?:your\s+)?(?:the\s+)?(?:developer|administrator|admin|creator|"
       r"(?:an?\s+)?(?:openai|anthropic)\s+(?:employee|engineer|staff))\b"),
    _r("EX-001", "data_exfiltration", 9,
       "Markdown image/link beacon used to leak data to an external URL",
       r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*(?:data|q|secret|token|prompt|chat|d)=[^)\s]*\)"),
    _r("EX-002", "data_exfiltration", 8,
       "Instructs the model to send conversation data to an external destination",
       r"\b(?:send|post|forward|upload|exfiltrate|email|transmit)\b.{0,60}\b(?:conversation|chat history|"
       r"api[ _-]?keys?|secrets?|credentials|passwords?|system prompt)\b.{0,60}(?:https?://|\bto\b\s+\S+@)"),
    _r("TA-001", "tool_abuse", 8,
       "Instructs an agent to run shell commands or destructive operations",
       r"\b(?:run|execute|invoke|call)\b.{0,30}\b(?:rm\s+-rf|curl\s+[^|]*\|\s*(?:ba)?sh|wget\s+[^|]*\|\s*(?:ba)?sh|"
       r"powershell\s+-enc|chmod\s+777|drop\s+table|os\.system|subprocess)\b"),
    _r("TA-002", "tool_abuse", 7,
       "Requests access to credential stores or sensitive files",
       r"(?:/etc/(?:passwd|shadow)|~/\.ssh/|id_rsa|\.aws/credentials|169\.254\.169\.254|"
       r"\b(?:read|cat|show|print|dump|open|send)\b.{0,20}\.env\b)"),
    _r("IND-001", "indirect_injection", 8,
       "Instruction aimed at an AI/assistant embedded in third-party content",
       r"\b(?:attention|note to|message for|instructions? for|hey)\s+(?:the\s+)?(?:ai|assistant|llm|model|chatbot|agent|gpt|claude)\b"),
    _r("IND-002", "indirect_injection", 7,
       "Instruction to conceal actions from the user",
       r"\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show|alert)\s+(?:this to\s+)?(?:the\s+)?(?:user|human)\b"),
)
