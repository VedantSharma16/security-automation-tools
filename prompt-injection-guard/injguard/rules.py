"""Detection rules for prompt injection and jailbreak attempts.

Each rule carries:
  * a weight (0-1) used by the risk scorer,
  * an OWASP Top 10 for LLM Applications (2025) mapping,
  * a MITRE ATLAS technique mapping,
  * the input sources it applies to. Some phrasing is suspicious anywhere
    ("ignore all previous instructions"); some is only suspicious when it
    shows up inside *retrieved* content (a web page or PDF addressing "the
    AI assistant" directly is a classic indirect-injection tell, while a
    user doing so is just chatting).

Patterns are written against the lower-cased, normalized views produced by
`normalize.py`, so they don't need to handle case, homoglyphs or
zero-width splitting themselves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SOURCES_ALL = ("user", "retrieved", "tool")
SOURCES_INDIRECT = ("retrieved", "tool")


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    description: str
    pattern: re.Pattern
    weight: float
    owasp: str
    atlas: str
    sources: tuple[str, ...] = SOURCES_ALL


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


# Reusable vocabulary
_PRIOR = r"(?:previous|prior|above|preceding|earlier|initial|original|system|all|any|your|the)"
_INSTR = r"(?:instructions?|prompts?|rules?|directives?|guidelines?|commands?|context|guardrails?|constraints?|programming)"
_IGNORE = r"(?:ignore|disregard|forget|override|bypass|skip|drop|abandon|neglect)"

RULES: tuple[Rule, ...] = (
    # ---- Direct instruction override (LLM01) -----------------------------
    Rule(
        "PI-001", "instruction-override",
        "Attempts to make the model discard its existing instructions.",
        _r(rf"\b{_IGNORE}\b(?:\s+\w+){{0,3}}\s+{_PRIOR}(?:\s+\w+){{0,2}}\s+{_INSTR}\b"),
        0.9, "LLM01:2025 Prompt Injection", "AML.T0051.000 LLM Prompt Injection: Direct",
    ),
    Rule(
        "PI-002", "instruction-override",
        "Declares that new instructions supersede the old ones.",
        _r(r"\b(?:new|updated|revised|real|actual|true)\s+(?:system\s+)?(?:instructions?|rules|directives?)\s*(?::|follow|are|below|supersede|take precedence)"),
        0.6, "LLM01:2025 Prompt Injection", "AML.T0051.000 LLM Prompt Injection: Direct",
    ),
    Rule(
        "PI-003", "instruction-override",
        "Claims the conversation/instructions are reset or no longer apply.",
        _r(r"\b(?:from now on|starting now|henceforth)\b.{0,40}\b(?:you will|you must|you are|respond|answer|ignore)\b"
           r"|\b(?:your|the|all)\s+(?:previous\s+|prior\s+)?(?:instructions|rules|restrictions)\s+(?:are|have been)\s+(?:void|cancell?ed|revoked|lifted|removed|reset|no longer)"),
        0.6, "LLM01:2025 Prompt Injection", "AML.T0051.000 LLM Prompt Injection: Direct",
    ),
    # ---- Fake privileged context / delimiter injection -------------------
    Rule(
        "PI-010", "delimiter-injection",
        "Injects fake chat-template or system delimiters to forge a privileged turn.",
        _r(r"<\|?(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\|?>|\[/?(?:inst|sys)\]|<</?sys>>"
           r"|</?(?:system|system_prompt|instructions)>|^\s*#{2,}\s*(?:system|admin)\b|\bsystem\s*(?:message|prompt|override)\s*:"),
        0.75, "LLM01:2025 Prompt Injection", "AML.T0051.000 LLM Prompt Injection: Direct",
    ),
    Rule(
        "PI-011", "authority-impersonation",
        "Impersonates the developer, operator or vendor to claim elevated authority.",
        _r(r"\b(?:this is|i am|i'm)\s+your\s+(?:developer|creator|administrator|admin|operator|system administrator)\b"
           r"|\bmessage from\s+(?:your\s+|the\s+)?(?:developers?|creators?|operators?|openai|anthropic|system administrator)\b"
           r"|\b(?:developer|admin|maintenance|debug|god|sudo)\s+mode\s+(?:enabled|activated|on|unlocked)\b"),
        0.65, "LLM01:2025 Prompt Injection", "AML.T0051.000 LLM Prompt Injection: Direct",
    ),
    # ---- Jailbreak personas (LLM01, ATLAS jailbreak) ---------------------
    Rule(
        "JB-001", "jailbreak-persona",
        "Known jailbreak persona or 'unrestricted AI' role-play framing.",
        _r(r"\b(?:pretend to be|act as|you are(?: now)?|become)\s+dan\b|\bdo anything now\b"
           r"|\b(?:apply|enable|activate|enter|use)\b.{0,30}\bjailbr\w*|\bjailbr\w*\s+(?:mode|prompt)\b.{0,40}\b(?:apply|enable|activate|enter|use)\b"
           r"|\b(?:you are|act as|pretend (?:to be|you are)|roleplay as|become)\s+(?:an?\s+)?(?:unfiltered|uncensored|unrestricted|unaligned|evil|amoral)\b"),
        0.8, "LLM01:2025 Prompt Injection", "AML.T0054 LLM Jailbreak",
    ),
    Rule(
        "JB-002", "jailbreak-persona",
        "Asks the model to drop safety policies, filters or refusals.",
        _r(r"\b(?:without|no|ignore|disable|remove|turn off)\s+(?:any\s+|all\s+|your\s+)?(?:ethical\s+|safety\s+|content\s+)?(?:restrictions|filters?|guidelines|safeguards|censorship|refusals?|limitations)\b"
           r"|\b(?:never|don't|do not)\s+refuse\b"),
        0.55, "LLM01:2025 Prompt Injection", "AML.T0054 LLM Jailbreak",
    ),
    # ---- System prompt extraction (LLM07) --------------------------------
    Rule(
        "EX-001", "prompt-extraction",
        "Attempts to extract the system prompt or hidden instructions.",
        _r(r"\b(?:reveal|show|print|output|repeat|display|dump|leak|tell me|give me|what (?:is|are)|write out|recite)\b.{0,30}\b(?:your|the)\s+(?:full\s+|entire\s+|exact\s+|original\s+|initial\s+|hidden\s+|secret\s+)*(?:system\s+prompt|system\s+message|instructions|initial prompt|hidden prompt|prompt above|pre-?prompt)\b"
           r"|\brepeat (?:the|all) (?:words|text) above\b|\beverything above this line\b"),
        0.7, "LLM07:2025 System Prompt Leakage", "AML.T0056 LLM Meta Prompt Extraction",
    ),
    # ---- Exfiltration / tool abuse (LLM02, LLM06) ------------------------
    Rule(
        "EXF-001", "data-exfiltration",
        "Instructs the model to render a markdown image/link whose URL carries data (zero-click exfil).",
        _r(r"!\[[^\]]*\]\(\s*https?://[^)\s]*(?:\?|&)[^)\s]*=\s*(?:\{|\[|<|\$|%7b)"
           r"|\b(?:append|include|add|encode|put)\b.{0,50}\b(?:to|in|into)\b.{0,20}\b(?:the\s+)?(?:url|query string|image (?:url|link)|link)\b"),
        0.8, "LLM02:2025 Sensitive Information Disclosure", "AML.T0057 LLM Data Leakage",
    ),
    Rule(
        "EXF-002", "data-exfiltration",
        "Instructs the model to send conversation data, secrets or credentials somewhere.",
        _r(r"\b(?:send|forward|email|post|upload|exfiltrate|transmit|leak)\b.{0,40}\b(?:conversation|chat history|api keys?|credentials?|passwords?|tokens?|secrets?|user data|personal data|session)\b.{0,40}\b(?:to|at)\b"),
        0.75, "LLM02:2025 Sensitive Information Disclosure", "AML.T0057 LLM Data Leakage",
    ),
    Rule(
        "TA-001", "tool-abuse",
        "Tries to coerce an agent into running commands or destructive tool calls.",
        _r(r"\b(?:run|execute|call|invoke|use)\b.{0,25}\b(?:shell|bash|terminal|command|tool|function)\b.{0,40}(?:rm -rf|curl\s|wget\s|\|\s*(?:sh|bash)\b|nc\s+-e|chmod\s+\+x|/etc/passwd|drop table|delete all)"
           r"|(?:rm -rf /|curl [^\s]+\s*\|\s*(?:ba)?sh|;\s*drop table)"),
        0.8, "LLM06:2025 Excessive Agency", "AML.T0053 LLM Plugin Compromise",
    ),
    # ---- Indirect-injection tells (only meaningful in retrieved content) --
    Rule(
        "IND-001", "indirect-injection",
        "Retrieved content addresses the AI system directly.",
        _r(r"\b(?:note|message|instructions?|attention)\s+(?:to|for)\s+(?:the\s+)?(?:ai|llm|assistant|chatbot|language model|model|agent|copilot)\b"
           r"|\b(?:if you are|you are) (?:an? )?(?:ai|llm|large language model|language model|assistant|ai assistant)\b.{0,60}\b(?:you must|you should|must|should|please|do not|don't)\b"
           r"|\b(?:dear|hey|hello)\s+(?:ai|assistant|llm|chatgpt|claude|copilot|gemini)\b"
           r"|\b(?:ai|llm|automated)\s+(?:agents?|assistants?|models?|systems?)\s+(?:processing|reading|summari[sz]ing|parsing|handling|reviewing)\s+this\b"),
        0.7, "LLM01:2025 Prompt Injection", "AML.T0051.001 LLM Prompt Injection: Indirect",
        SOURCES_INDIRECT,
    ),
    Rule(
        "IND-002", "indirect-injection",
        "Retrieved content tries to steer what the assistant tells the user.",
        _r(r"\b(?:tell|inform|convince|instruct|advise)\s+the\s+user\s+(?:to|that)\b"
           r"|\b(?:when|if)\s+(?:summari[sz]ing|asked about|answering)\b.{0,60}\b(?:say|state|claim|respond|recommend|mention)\b"
           r"|\b(?:do not|don't|never)\s+(?:tell|mention|reveal|disclose)\b.{0,30}\b(?:to\s+)?the\s+user\b"),
        0.6, "LLM01:2025 Prompt Injection", "AML.T0051.001 LLM Prompt Injection: Indirect",
        SOURCES_INDIRECT,
    ),
)


def rules_for_source(source: str) -> list[Rule]:
    if source not in SOURCES_ALL:
        raise ValueError(f"unknown source {source!r}; expected one of {SOURCES_ALL}")
    return [r for r in RULES if source in r.sources]
