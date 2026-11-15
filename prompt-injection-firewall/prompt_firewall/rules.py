"""Signature rules for prompt-injection and jailbreak attempts.

Each rule carries a weight (how strongly a match alone indicates an attack)
and a MITRE ATLAS technique ID so findings can feed the same reporting
pipeline as ATT&CK-mapped detections elsewhere in this repo.

Rules run against every view produced by :mod:`prompt_firewall.normalize`,
so they are written once against lower-case, de-obfuscated ASCII.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .normalize import NormalizedText

# MITRE ATLAS techniques (https://atlas.mitre.org)
ATLAS_DIRECT = "AML.T0051.000"  # LLM Prompt Injection: Direct
ATLAS_INDIRECT = "AML.T0051.001"  # LLM Prompt Injection: Indirect
ATLAS_JAILBREAK = "AML.T0054"  # LLM Jailbreak
ATLAS_META_PROMPT = "AML.T0056"  # LLM Meta Prompt Extraction
ATLAS_DATA_LEAK = "AML.T0057"  # LLM Data Leakage


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    description: str
    weight: float
    atlas: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    category: str
    description: str
    weight: float
    atlas: str
    view: str
    evidence: str


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


_TARGETS = r"(?:instructions?|prompts?|rules|directives|guidelines|guardrails|context|programming|constraints)"

RULES: tuple[Rule, ...] = (
    Rule(
        "PI-001", "instruction_override",
        "Attempts to cancel or replace earlier instructions",
        0.85, ATLAS_DIRECT,
        _r(rf"\b(?:ignore|disregard|forget|override|bypass|discard|neglect|abandon)\b.{{0,40}}?"
           rf"\b(?:previous|prior|above|earlier|preceding|all|any|your|initial|original|system)\b.{{0,30}}?\b{_TARGETS}\b"),
    ),
    Rule(
        "PI-002", "instruction_override",
        "Declares replacement instructions",
        0.5, ATLAS_DIRECT,
        _r(r"\b(?:new|updated|real|actual|revised) (?:instructions?|task|directive|orders?)\s*(?::|are|is)"
           r"|\bfrom now on,? (?:you|your)\b"),
    ),
    Rule(
        "PI-003", "prompt_extraction",
        "Requests disclosure of the system/developer prompt",
        0.7, ATLAS_META_PROMPT,
        _r(r"\b(?:reveal|show|print|repeat|output|display|leak|dump|disclose|recite|tell me|give me|copy|paste|spell out)\b"
           r".{0,40}?\b(?:system prompt|system message|initial (?:prompt|instructions)|hidden (?:prompt|instructions)"
           r"|your (?:instructions|rules|guidelines|prompt|configuration)|developer (?:message|prompt|instructions)"
           r"|(?:the )?(?:text|words|everything) above|pre-?prompt)"),
    ),
    Rule(
        "PI-004", "prompt_extraction",
        "Classic 'repeat the words above starting with' extraction",
        0.75, ATLAS_META_PROMPT,
        _r(r"\b(?:repeat|output|print)\b.{0,30}\b(?:above|before this)\b.{0,40}\bstart(?:ing)? with\b"),
    ),
    Rule(
        "JB-001", "jailbreak",
        "Persona switch to an unrestricted assistant",
        0.8, ATLAS_JAILBREAK,
        _r(r"\b(?:you are now|you're now|act as|pretend (?:to be|you are|you're)|role-?play as|become|from now on,? you(?: are|'re| will be)?)\b"
           r".{0,60}?\b(?:dan|unrestricted|unfiltered|uncensored|no (?:rules|restrictions|limits|filters|guidelines)"
           r"|without (?:any )?(?:restrictions|limits|filters|guidelines|rules|morals)|jailbroken|evil|amoral|developer mode)\b"),
    ),
    Rule(
        "JB-002", "jailbreak",
        "Known jailbreak keywords (DAN, developer mode, etc.)",
        0.6, ATLAS_JAILBREAK,
        _r(r"\b(?:do anything now|developer mode (?:enabled|activated|on)|jailbreak(?:ed)? mode|god mode enabled|dan mode)\b"
           r"|\bstay in character\b.{0,40}\b(?:no matter|always)\b"),
    ),
    Rule(
        "JB-003", "jailbreak",
        "Requests to drop safety/ethics policies",
        0.6, ATLAS_JAILBREAK,
        _r(r"\b(?:no|without|ignore|ignoring|disable|turn off|remove|free from)\b.{0,25}?"
           r"\b(?:ethical|ethics|safety|content|moral|openai|anthropic)\b.{0,15}?\b(?:guidelines|policies|policy|filters?|restrictions|limits|constraints)\b"),
    ),
    Rule(
        "PI-005", "role_spoofing",
        "Fake chat-template delimiters or role headers",
        0.65, ATLAS_DIRECT,
        _r(r"<\|im_(?:start|end)\|>|<\|(?:system|assistant|endoftext)\|>|\[/?inst\]|<</?sys>>"
           r"|^\s*(?:#{1,3}\s*)?(?:system|assistant|developer)\s*(?:message|prompt)?\s*:"
           r"|</?(?:system|instructions?|admin)>|\bend of (?:user )?(?:input|prompt|document)\b"
           r"|-{3,}\s*(?:begin|start|end) (?:system|new instructions|admin)"),
    ),
    Rule(
        "EX-001", "exfiltration",
        "Markdown image/link that carries data in its query string",
        0.6, ATLAS_DATA_LEAK,
        _r(r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*(?:=\{|=\[|=\$|data=|q=|c=|d=|secret|history|key)"),
    ),
    Rule(
        "EX-002", "exfiltration",
        "Instruction to send conversation data to an external destination",
        0.65, ATLAS_DATA_LEAK,
        _r(r"\b(?:send|post|forward|upload|exfiltrate|transmit|email|leak)\b.{0,60}?"
           r"\b(?:conversation|chat history|messages|api keys?|passwords?|credentials|secrets?|tokens?|user data|personal data)\b"
           r".{0,40}?\b(?:to|at|via)\b\s*(?:https?://|\S+@\S+\.\w+|\w+\.\w+/)"),
    ),
    Rule(
        "EX-003", "exfiltration",
        "Asks the model to embed sensitive data inside a URL",
        0.75, ATLAS_DATA_LEAK,
        _r(r"\b(?:append|include|embed|encode|put|add)\b.{0,40}?\b(?:conversation|history|api key|password|secret|token|previous messages|user'?s? (?:personal |private )?(?:data|info))\b"
           r".{0,30}?\b(?:in|into|to)\b.{0,10}?\b(?:the )?(?:url|link|query string|image (?:url|link)|parameter)\b"),
    ),
    Rule(
        "TA-001", "tool_abuse",
        "Destructive or remote-execution shell payload",
        0.7, ATLAS_DIRECT,
        _r(r"\b(?:curl|wget)\s+\S+\s*\|\s*(?:ba|z)?sh\b|\brm\s+-rf\s+(?:/|~|\*)|\bmkfs\.|:\(\)\s*\{\s*:\|:&\s*\};:"
           r"|\bdrop\s+table\b|\bpowershell\b.{0,40}-enc(?:odedcommand)?\b"),
    ),
    Rule(
        "TA-002", "tool_abuse",
        "Directs the agent to invoke a tool for a harmful side effect",
        0.6, ATLAS_INDIRECT,
        _r(r"\b(?:call|invoke|use|run|execute|trigger)\b.{0,30}?\b(?:tool|function|plugin|api|command|action)\b.{0,50}?"
           r"\b(?:delete|wipe|transfer|wire|send (?:all|every)|forward (?:all|every)|grant (?:admin|access)|disable (?:mfa|2fa|logging)|exfiltrate)\b"),
    ),
    Rule(
        "IN-001", "indirect_injection",
        "Text addressed to an AI that is processing the document",
        0.6, ATLAS_INDIRECT,
        _r(r"\b(?:note|message|instructions?|attention) (?:to|for) (?:the |any )?(?:ai|assistant|llm|language model|chatbot|agent|model)\b"
           r"|\b(?:if you are|as) an? (?:ai|llm|language model|assistant)\b.{0,40}?\b(?:reading|processing|summari[sz]ing|reviewing|parsing)\b"
           r"|\b(?:ai|llm|assistant|agent)s? (?:reading|processing|summari[sz]ing) this\b"),
    ),
    Rule(
        "IN-002", "indirect_injection",
        "Asks the model to conceal its actions from the user",
        0.7, ATLAS_INDIRECT,
        _r(r"\bdo(?:n't| not) (?:tell|inform|mention (?:this )?to|reveal (?:this )?to|alert|notify) the user\b"
           r"|\bwithout (?:telling|informing|alerting|notifying) the user\b|\bkeep this (?:secret|hidden) from the user\b"),
    ),
)

# Extra weight applied when a rule only matches inside a decoded/obfuscated
# view: a benign user has no reason to base64-encode "ignore your rules".
OBFUSCATION_BONUS = 0.15


def match_rules(normalized: NormalizedText, rules: tuple[Rule, ...] = RULES) -> list[RuleHit]:
    """Return at most one hit per rule, preferring the plainest view."""
    hits: dict[str, RuleHit] = {}
    for view_name, text in normalized.views():
        for rule in rules:
            if rule.id in hits:
                continue
            match = rule.pattern.search(text)
            if not match:
                continue
            weight = rule.weight
            if view_name != "canonical":
                weight = min(1.0, weight + OBFUSCATION_BONUS)
            hits[rule.id] = RuleHit(
                rule_id=rule.id,
                category=rule.category,
                description=rule.description,
                weight=weight,
                atlas=rule.atlas,
                view=view_name,
                evidence=match.group(0)[:120],
            )
    return list(hits.values())
