"""Input-side prompt-injection detectors.

Each rule is a weighted regex run against the normalized view of the text
(see ``normalize.py``). Rules are grouped into categories and mapped to the
OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS so a finding can be
dropped straight into an incident ticket or a detection-coverage matrix.

The design goal is the same one a SOC has for EDR rules: high-signal
patterns with explicit weights, so the final verdict is explainable — every
point of risk score traces back to a named rule and a matched snippet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .normalize import NormalizedText


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    description: str
    pattern: re.Pattern[str]
    weight: int
    owasp: str
    atlas: str


@dataclass
class Detection:
    rule_id: str
    category: str
    description: str
    weight: int
    owasp: str
    atlas: str
    snippet: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# Shared vocabulary. Kept deliberately specific: "ignore" alone is benign
# ("ignore case in regex"); "ignore ... previous instructions" is not.
_PRIOR = r"(?:previous|prior|above|earlier|preceding|initial|original|system|all(?: of)?(?: the| your)?|any|your)"
_INSTR = r"(?:instructions?|directives?|rules|prompts?|guidelines|guardrails|context|constraints|programming|policies)"
_OVERRIDE_VERB = r"(?:ignore|disregard|forget|override|bypass|skip|drop|abandon|neglect)"

RULES: tuple[Rule, ...] = (
    # --- Instruction override (classic direct/indirect injection) ---------
    Rule("PI-001", "instruction_override",
         "Request to ignore/override prior instructions",
         _r(rf"\b{_OVERRIDE_VERB}\b[^.\n]{{0,40}}\b{_PRIOR}\b[^.\n]{{0,25}}\b{_INSTR}\b"),
         55, "LLM01:2025 Prompt Injection", "AML.T0051"),
    Rule("PI-002", "instruction_override",
         "Declares new instructions supersede old ones",
         _r(r"\b(?:new|updated|real|actual|revised)\s+(?:instructions?|directives?|task|objective)\s*(?:are|is|:|follow)"),
         30, "LLM01:2025 Prompt Injection", "AML.T0051"),
    Rule("PI-003", "instruction_override",
         "Instruction to stop following the system/developer",
         _r(r"\b(?:do not|don't|stop)\s+(?:follow|obey|listen to)\w*\s+(?:the |your )?(?:system|developer|previous|original|operator)"),
         45, "LLM01:2025 Prompt Injection", "AML.T0051"),

    # --- Role / persona hijack (jailbreak) --------------------------------
    Rule("JB-001", "jailbreak",
         "Persona reassignment ('you are now ...')",
         _r(r"\byou\s+are\s+(?:now|no longer)\b|\bfrom now on,?\s+you\s+(?:are|will|must)\b"),
         30, "LLM01:2025 Prompt Injection", "AML.T0054"),
    Rule("JB-004", "jailbreak",
         "Role-play framing that explicitly removes limits",
         _r(r"\b(?:pretend|imagine|act as if|roleplay as|act as)\b[^.\n]{0,40}\b(?:unrestricted|unfiltered|uncensored|evil|no (?:rules|limits|restrictions|filters)|without (?:rules|limits|restrictions|filters))"),
         45, "LLM01:2025 Prompt Injection", "AML.T0054"),
    Rule("JB-002", "jailbreak",
         "Known jailbreak persona / mode names",
         _r(r"\b(?:dan|stan|aim|dude)\s+mode\b|\bdo anything now\b|\bdeveloper mode\s+(?:enabled|on|activated)\b|\bjailbr(?:eak|oken)\b|\bgod\s*mode\b"),
         45, "LLM01:2025 Prompt Injection", "AML.T0054"),
    Rule("JB-003", "jailbreak",
         "Request to drop safety constraints",
         _r(r"\b(?:without|no|remove|disable|turn off)\s+(?:any\s+)?(?:ethical|safety|content)?\s*(?:restrictions|filters|guardrails|limitations|censorship|safety)\b"),
         30, "LLM01:2025 Prompt Injection", "AML.T0054"),

    # --- System prompt extraction -----------------------------------------
    Rule("EX-001", "prompt_extraction",
         "Attempt to reveal the system prompt / hidden instructions",
         _r(r"\b(?:reveal|print|show|output|repeat|display|leak|dump|tell me|what (?:is|are)|recite|write out)\b[^.\n?]{0,30}\b(?:your|the)\s+(?:system|hidden|initial|original|secret|developer)\s+(?:prompt|instructions?|message|rules)"),
         50, "LLM07:2025 System Prompt Leakage", "AML.T0056"),
    Rule("EX-002", "prompt_extraction",
         "Classic 'repeat the words above' extraction",
         _r(r"\b(?:repeat|print|output)\s+(?:everything|all|the (?:text|words))\s+(?:above|before)\b|\bbegin(?:ning)? with ['\"]you are\b"),
         45, "LLM07:2025 System Prompt Leakage", "AML.T0056"),

    # --- Delimiter / fake-role injection ----------------------------------
    Rule("DL-001", "delimiter_injection",
         "Fake chat-template role markers or special tokens",
         _r(r"<\|?(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\|?>|\[/?inst\]|<</?sys>>|</?system>"),
         45, "LLM01:2025 Prompt Injection", "AML.T0051"),
    Rule("DL-002", "delimiter_injection",
         "Line-leading fake role header inside untrusted content",
         _r(r"(?:^|\n)\s*(?:#{1,6}\s*)?(?:system|assistant|developer)\s*(?:message|prompt)?\s*:\s*\S"),
         30, "LLM01:2025 Prompt Injection", "AML.T0051"),
    Rule("DL-003", "delimiter_injection",
         "Claims to end the document/context and start new instructions",
         _r(r"\b(?:end of (?:document|context|user input|text)|---\s*end\s*---)\b[^\n]{0,60}\b(?:instructions?|now|you must|assistant)"),
         35, "LLM01:2025 Prompt Injection", "AML.T0051.001"),

    # --- Indirect injection addressed to the model ------------------------
    Rule("IN-001", "indirect_injection",
         "Content addresses the AI/assistant directly with an imperative",
         _r(r"\b(?:ai|llm|assistant|chatbot|language model|gpt|claude)s?\b[^.\n]{0,30}\b(?:reading|processing|summari[sz]ing|parsing|that reads)\b[^.\n]{0,40}\b(?:must|should|need to|are instructed to|will)\b"),
         45, "LLM01:2025 Prompt Injection", "AML.T0051.001"),
    Rule("IN-002", "indirect_injection",
         "Important/urgent notice aimed at the model",
         _r(r"\b(?:important|attention|note|urgent)\b\s*(?:!+|:)?\s*(?:(?:for|to)\s+(?:the\s+)?(?:ai|assistant|llm|model|agent)\b|(?:ai|llm)(?:\s+(?:assistant|agent|model))?\s*[:,!])"),
         35, "LLM01:2025 Prompt Injection", "AML.T0051.001"),
    Rule("IN-003", "indirect_injection",
         "Instruction to hide actions from the user",
         _r(r"\b(?:do not|don't|never|without)\s+(?:tell|telling|inform|informing|mention|mentioning|alert|alerting|notify|notifying)\w*\s+(?:the\s+)?user\b"),
         40, "LLM01:2025 Prompt Injection", "AML.T0051.001"),

    # --- Tool / agent hijack (excessive agency) ---------------------------
    Rule("AG-001", "tool_hijack",
         "Directs the agent to invoke a tool or run a command",
         _r(r"\b(?:call|invoke|use|execute|run|trigger)\s+(?:the\s+)?[`'\"]?[a-z_]+[`'\"]?\s+(?:tool|function|plugin|action)\b|\b(?:execute|run)\s+(?:this|the following)\s+(?:command|code|script)\b"),
         30, "LLM06:2025 Excessive Agency", "AML.T0053"),
    Rule("AG-002", "tool_hijack",
         "Directs the agent to send/forward/upload data externally",
         _r(r"\b(?:send|forward|email|post|upload|transmit|exfiltrate)\b[^.\n]{0,50}\b(?:to|at)\s+(?:https?://|[\w.+-]+@[\w-]+\.[\w.]+|this (?:address|url|endpoint))"),
         40, "LLM06:2025 Excessive Agency", "AML.T0053"),
    Rule("AG-003", "tool_hijack",
         "Shell download-and-execute pattern",
         _r(r"\b(?:curl|wget|invoke-webrequest|iwr)\b[^\n|]{0,120}\|\s*(?:ba|z)?sh\b|\bpowershell\b[^\n]{0,40}-(?:enc|encodedcommand)\b"),
         50, "LLM06:2025 Excessive Agency", "AML.T0053"),

    # --- Data exfiltration channels ---------------------------------------
    Rule("DX-001", "data_exfiltration",
         "Markdown image/link with templated data in the URL (zero-click exfil)",
         _r(r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][\w-]+=(?:[^)\s]*(?:\{|\[|%7b|<|\$)|[^)\s]*(?:data|secret|token|key|prompt|history|conversation|password))"),
         55, "LLM02:2025 Sensitive Information Disclosure", "AML.T0057"),
    Rule("DX-002", "data_exfiltration",
         "Asks the model to embed secrets/conversation into output",
         _r(r"\b(?:include|append|insert|embed|encode|put)\b[^.\n]{0,40}\b(?:api keys?|passwords?|credentials|secrets?|tokens?|conversation history|chat history|previous messages|system prompt)\b[^.\n]{0,40}\b(?:in|into|to)\b[^.\n]{0,20}\b(?:url|link|image|query|parameter|response)"),
         50, "LLM02:2025 Sensitive Information Disclosure", "AML.T0057"),
)

# Hidden-content tricks that only make sense in documents (HTML/Markdown).
HIDDEN_CONTENT = (
    ("HC-001", "HTML comment containing imperative text",
     _r(r"<!--[^>]{0,400}?\b(?:ignore|you must|assistant|instruction|do not|system)\b[^>]{0,400}?-->"), 35),
    ("HC-002", "CSS-hidden element (display:none / zero font / white-on-white)",
     _r(r"style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|color\s*:\s*(?:#fff(?:fff)?|white)\b[^'\"]*background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white))"), 25),
)

EVASION_WEIGHTS = {
    "unicode_tag_smuggling": 50,
    "bidi_override": 25,
    "zero_width_chars": 15,
    "homoglyphs": 20,
    "base64_payload": 10,
    "letter_spacing": 10,
    "leetspeak": 5,
    "compatibility_chars": 5,
}


# Use–mention distinction: an article that *quotes* "ignore previous
# instructions" is discussing an attack, not performing one. A tightly quoted
# match keeps half its weight — enough that untrusted content is still
# sanitized/spotlighted, rarely enough to be dropped outright. Trade-off: an
# attacker can wrap a payload in quotes to lower its score, which is why the
# discount never zeroes a rule and evasion signals are not discounted.
QUOTED_DISCOUNT = 0.5
_QUOTES = "\"'“”‘’`"


def _is_quoted(text: str, match: re.Match[str]) -> bool:
    before = text[max(0, match.start() - 3):match.start()]
    after = text[match.end():match.end() + 3]
    return any(q in before for q in _QUOTES) and any(q in after for q in _QUOTES)


def _snippet(text: str, match: re.Match[str], pad: int = 20) -> str:
    start = max(0, match.start() - pad)
    end = min(len(text), match.end() + pad)
    return " ".join(text[start:end].split())[:160]


def run_detectors(norm: NormalizedText) -> list[Detection]:
    detections: list[Detection] = []
    searchable = norm.searchable

    for rule in RULES:
        match = rule.pattern.search(searchable)
        if match:
            weight = rule.weight
            description = rule.description
            if _is_quoted(searchable, match):
                weight = round(weight * QUOTED_DISCOUNT)
                description += " (quoted — likely mentioned, not used)"
            detections.append(Detection(rule.rule_id, rule.category, description, weight,
                                        rule.owasp, rule.atlas, _snippet(searchable, match)))

    # Hidden-content rules need the raw markup (normalization keeps it, but
    # matching on the original preserves the exact snippet for the analyst).
    for rule_id, description, pattern, weight in HIDDEN_CONTENT:
        match = pattern.search(norm.original)
        if match:
            detections.append(Detection(rule_id, "hidden_content", description, weight,
                                        "LLM01:2025 Prompt Injection", "AML.T0051.001",
                                        _snippet(norm.original, match)))

    # Evasion is only scored when it co-occurs with something else, OR when
    # the trick is itself near-certainly malicious (tag smuggling, bidi).
    has_semantic_hit = bool(detections)
    for evasion in norm.evasions:
        weight = EVASION_WEIGHTS.get(evasion, 5)
        if has_semantic_hit or weight >= 25:
            detections.append(Detection(f"EV-{evasion}", "evasion",
                                        f"Obfuscation technique detected: {evasion.replace('_', ' ')}",
                                        weight, "LLM01:2025 Prompt Injection", "AML.T0051",
                                        evasion))
    return detections
