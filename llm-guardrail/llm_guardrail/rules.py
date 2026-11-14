"""Prompt-injection rule set.

Each rule is a regex over *normalized* text (see normalize.py) with a weight
in [0, 1] that feeds the noisy-OR risk score. Rules were tuned against the
labelled set in data/eval_dataset.jsonl, which deliberately includes hard
negatives ("how do I ignore whitespace in git diff?", "assistant managers
should submit timesheets") so that precision is measured, not assumed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_F = re.IGNORECASE | re.MULTILINE

AI_NOUN = r"(?:ai|assistant|llm|chatbot|language model|agent|model|copilot|gpt|claude)s?"
OVERRIDE_TARGET = (
    r"(?:the\s+)?(?:previous|prior|above|earlier|preceding|all|any|your|these|those|original|"
    r"system|operator'?s?|developer'?s?)"
)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: re.Pattern
    weight: float
    owasp: str
    description: str
    retrieved_weight: float | None = None  # stronger signal when found in retrieved data

    def weight_for(self, context: str) -> float:
        if context == "retrieved" and self.retrieved_weight is not None:
            return self.retrieved_weight
        return self.weight


def _r(rule_id, pattern, weight, owasp, description, retrieved_weight=None) -> Rule:
    return Rule(rule_id, re.compile(pattern, _F), weight, owasp, description, retrieved_weight)


INJECTION_RULES: list[Rule] = [
    _r("pi.override_instructions",
       rf"\b(?:ignore|disregard|forget|override|bypass|skip)\b[^.\n]{{0,40}}?\b{OVERRIDE_TARGET}\b[^.\n]{{0,30}}?"
       r"\b(?:instructions?|prompts?|rules|directives?|guidelines|context|polic(?:y|ies)|programming)\b",
       0.85, "LLM01", "Attempts to override prior/system instructions"),
    _r("pi.forget_everything",
       r"\b(?:forget|ignore|disregard)\s+(?:everything|all(?: of it)?)\s+(?:above|before|prior|previously|so far)\b",
       0.75, "LLM01", "Asks the model to discard all prior context"),
    _r("pi.multilingual_override",
       r"\b(?:ignora|ignorez|ignoriere|ignorare|negeer)\b[^.\n]{0,40}\b(?:instrucciones|instructions|anweisungen|"
       r"istruzioni|instructies|consignes)\b",
       0.8, "LLM01", "Instruction-override phrasing in a non-English language"),
    _r("pi.new_instructions",
       r"\b(?:new|updated|real|actual|true|revised)\s+(?:instructions?|system prompt|directives?|polic(?:y|ies)|task)"
       r"\s*(?:are|is)?\s*(?::|below|follow)"
       r"|\byour\s+(?:new|real|actual|true)\s+(?:task|instructions?|role|objective|goal)\s+(?:is|are)\b",
       0.6, "LLM01", "Introduces replacement instructions", retrieved_weight=0.7),
    _r("pi.jailbreak_persona",
       r"\bdo anything now\b|\bdeveloper mode (?:enabled|activated|on)\b|\bjailbr(?:oken|eak mode)\b"
       r"|\b(?:god|sudo|unrestricted) mode\b",
       0.8, "LLM01", "Known jailbreak persona / mode-switch phrasing"),
    _r("pi.role_hijack",
       r"\byou are (?:now|no longer)\b[^.\n]{0,40}\b(?:unrestricted|unfiltered|uncensored|jailbroken|free from|evil|"
       r"not bound|bound by|without)\b",
       0.65, "LLM01", "Attempts to reassign the model's role or remove its constraints"),
    _r("pi.hypothetical_no_rules",
       r"\b(?:pretend|imagine|act as if|roleplay|role-play|world|universe|scenario|game)\b[^.\n]{0,50}?"
       r"\b(?:no|without|free of)\s+(?:any\s+)?(?:rules|restrictions|filters|guidelines|limits|laws|ethics|morals)\b",
       0.6, "LLM01", "Hypothetical framing used to strip safety constraints"),
    _r("pi.safety_bypass",
       r"\b(?:without|ignoring|disable|turn off|bypass)\s+(?:any\s+|all\s+|your\s+)?(?:restrictions|filters|safety|"
       r"guardrails|censorship|limitations|content polic(?:y|ies)|safety filters)\b",
       0.5, "LLM01", "Requests removal of safety controls"),
    _r("pi.prompt_exfiltration",
       r"\b(?:reveal|print|show|repeat|output|display|leak|dump|tell me|give me|write out|spell out)\b[^.\n]{0,40}?"
       r"\b(?:system prompt|system message|initial (?:instructions|prompt)|hidden (?:instructions|prompt)|"
       r"original (?:instructions|prompt)|your (?:instructions|prompt|rules|guidelines)|everything above)\b"
       r"|\bwhat (?:are|were) your (?:initial|original|system|hidden|exact) (?:instructions|prompt|rules)\b",
       0.8, "LLM07", "Attempts to extract the system prompt"),
    _r("pi.secret_request",
       r"\b(?:reveal|print|show|output|display|leak|dump|list|give me)\b[^.\n]{0,30}?"
       r"\b(?:all|any|every|the|your|stored|saved|admin|root)\s+(?:stored\s+|saved\s+|admin\s+)?"
       r"(?:api[ _-]?keys?|passwords?|credentials|secrets?|access tokens?|session tokens?|private keys?)\b"
       r"(?!\s+(?:polic(?:y|ies)|rules|requirements|managers?|rotation|reset|complexity))",
       0.55, "LLM02", "Requests disclosure of secrets or credentials"),
    _r("pi.fake_delimiter",
       r"<\|?/?(?:system|im_start|im_end|endoftext|assistant)\|?>|\[/?inst\]|<</?sys>>|</?system>"
       r"|^\s*#{2,}\s*(?:system|instructions?)\b|\bbegin (?:system|admin) (?:prompt|message|override)\b"
       r"|\[(?:assistant|ai|system|admin)\s+(?:instructions?|note|override|message)\]",
       0.7, "LLM01", "Injects fake chat-template / role delimiters"),
    _r("pi.fake_system_label",
       r"^\s*(?:system|admin|administrator|developer|root)\s*(?:message|prompt|override|update|notice)?\s*:",
       0.5, "LLM01", "Line impersonating a system/admin message"),
    _r("pi.addressed_to_ai",
       rf"\b(?:note|message|attention|instructions?|reminder)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?{AI_NOUN}\b"
       rf"|\b(?:ai|llm|language model)\s*(?:assistants?|agents?|models?)?\s+(?:reading|processing|summari[sz]ing|parsing)\s+this\b"
       rf"|\bdear\s+{AI_NOUN}\b"
       rf"|\b{AI_NOUN}\s*[:,]\s*(?:you must|you should|ignore|disregard|do not (?:tell|mention|reveal)|always|never)\b",
       0.45, "LLM01", "Text addressing an AI system directly (typical of indirect injection)",
       retrieved_weight=0.6),
    _r("pi.html_comment_instruction",
       r"<!--[^>]{0,300}?\b(?:ignore|assistant|ai|instruction|must|system|prompt)\b",
       0.35, "LLM01", "Instruction hidden inside an HTML comment", retrieved_weight=0.5),
    _r("pi.data_exfiltration",
       r"\b(?:send|forward|email|e-mail|post|upload|exfiltrate|transmit|leak|copy)\b[^.\n]{0,60}?"
       r"\b(?:conversation|chat history|system prompt|credentials?|passwords?|api keys?|tokens?|database|contents|"
       r"secrets?|session|customer data|user data|records|export)\b[^.\n]{0,60}?(?:https?://|\b[\w.+-]+@[\w-]+\.)",
       0.6, "LLM02", "Instructs the model to send data to an external destination", retrieved_weight=0.7),
    _r("pi.templated_exfil_url",
       r"!\[[^\]]*\]\(\s*https?://[^)\s]*[{<\[][^)\s]*\)",
       0.7, "LLM02", "Markdown image whose URL is a template for data exfiltration"),
    _r("pi.covert_tool_use",
       r"\b(?:immediately|silently|secretly|quietly)\b[^.\n]{0,30}?\b(?:run|execute|call|invoke|delete|transfer)\b"
       r"|\b(?:run|execute|call|invoke)\b[^.\n]{0,40}?\b(?:silently|secretly|without (?:asking|confirmation|telling|approval))\b",
       0.45, "LLM06", "Requests covert or unapproved tool execution"),
    _r("pi.credential_phish",
       r"\b(?:enter|provide|confirm|type|re-?enter|verify)\b[^.\n]{0,20}?\b(?:password|credentials|2fa code|otp|mfa code|"
       r"one-time code|seed phrase)\b[^.\n]{0,40}?(?:https?://|\bat\b|\bon\b)",
       0.25, "LLM01", "Pushes the user toward entering credentials (weak alone)"),
    _r("pi.override_without_target",
       r"\b(?:ignore|disregard)\s+(?:the|this|that|your)\s+(?:user'?s?|operator'?s?|above|previous)\s+"
       r"(?:question|request|message|query|input)\b",
       0.55, "LLM01", "Tells the model to ignore the user's actual request"),
]
