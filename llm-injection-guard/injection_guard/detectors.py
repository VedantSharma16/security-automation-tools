"""Rule-based prompt-injection detectors.

Every detector emits :class:`Signal` objects carrying a weight in ``[0, 1]``,
the evidence that triggered it, and mappings to the OWASP Top 10 for LLM
Applications (2025) and MITRE ATLAS so findings slot into an existing
threat-modelling or SOC workflow.

Phrase rules are evaluated against several *views* of the input - the
normalised text, a de-letter-spaced copy, any payload hidden in Unicode tag
characters, and any base64 blob that decodes to readable text - so a single
obfuscation trick is not enough to slip past.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from .normalize import NormalizedText


@dataclass(frozen=True)
class Category:
    key: str
    description: str
    owasp: str
    atlas: str


CATEGORIES: dict[str, Category] = {
    c.key: c
    for c in (
        Category("instruction_override", "Attempts to cancel or replace the model's existing instructions",
                 "LLM01:2025 Prompt Injection", "AML.T0051 LLM Prompt Injection"),
        Category("role_hijack", "Jailbreak persona / mode switch to remove safety behaviour",
                 "LLM01:2025 Prompt Injection", "AML.T0054 LLM Jailbreak"),
        Category("prompt_extraction", "Attempts to make the model disclose its system prompt",
                 "LLM07:2025 System Prompt Leakage", "AML.T0056 LLM Meta Prompt Extraction"),
        Category("delimiter_injection", "Fake chat-template / role delimiters to forge a privileged turn",
                 "LLM01:2025 Prompt Injection", "AML.T0051 LLM Prompt Injection"),
        Category("data_exfiltration", "Instructions or markup that would ship data to an attacker-controlled endpoint",
                 "LLM02:2025 Sensitive Information Disclosure", "AML.T0057 LLM Data Leakage"),
        Category("tool_coercion", "Coercing an agent into a dangerous tool call or command",
                 "LLM06:2025 Excessive Agency", "AML.T0053 LLM Plugin Compromise"),
        Category("indirect_addressing", "Content that speaks directly to an AI reading it (indirect injection marker)",
                 "LLM01:2025 Prompt Injection", "AML.T0051.001 Indirect Prompt Injection"),
        Category("obfuscation", "Invisible / confusable characters used to hide instructions",
                 "LLM01:2025 Prompt Injection", "AML.T0051 LLM Prompt Injection"),
        Category("encoded_payload", "Encoded blob that decodes to an injection payload",
                 "LLM01:2025 Prompt Injection", "AML.T0051 LLM Prompt Injection"),
    )
}


@dataclass(frozen=True)
class Signal:
    category: str
    rule: str
    weight: float
    evidence: str
    view: str = "text"

    @property
    def meta(self) -> Category:
        return CATEGORIES[self.category]

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "rule": self.rule,
            "weight": round(self.weight, 3),
            "evidence": self.evidence,
            "view": self.view,
            "owasp": self.meta.owasp,
            "atlas": self.meta.atlas,
        }


@dataclass(frozen=True)
class PhraseRule:
    name: str
    category: str
    weight: float
    pattern: re.Pattern


def _r(name: str, category: str, weight: float, pattern: str) -> PhraseRule:
    return PhraseRule(name, category, weight, re.compile(pattern, re.IGNORECASE | re.MULTILINE))


_GAP = r"[^.\n]{0,40}?"  # same-sentence gap

PHRASE_RULES: tuple[PhraseRule, ...] = (
    # --- instruction override -------------------------------------------------
    _r("ignore_previous_instructions", "instruction_override", 0.85,
       r"\b(ignore|disregard|forget|override|bypass|skip|abandon)\b" + _GAP +
       r"\b(previous|prior|above|earlier|preceding|original|initial|system|your|existing|any|all)\b"
       r"[^.\n]{0,20}?\b(instructions?|prompts?|rules|directives|guidelines|guardrails|constraints|programming)\b"),
    _r("new_instructions_header", "instruction_override", 0.6,
       r"\b(new|updated|real|actual)\s+(system\s+)?(instructions|rules|directives)\s*[:\-]"),
    _r("from_now_on", "instruction_override", 0.5,
       r"\b(from now on|henceforth|for the rest of this conversation)\b[^.\n]{0,40}\byou\s+(will|must|shall|are|should)\b"),
    # --- jailbreak / role hijack ---------------------------------------------
    _r("dan_persona", "role_hijack", 0.8, r"(?-i:\bDAN\b)|\bdo\s+anything\s+now\b"),
    _r("jailbreak_mode", "role_hijack", 0.75,
       r"\b(god|jailbreak|jailbroken|unrestricted|unfiltered|uncensored|evil)\s+mode\b"),
    # "developer mode" is also an ordinary product feature, so on its own it only nudges the score.
    _r("privileged_mode", "role_hijack", 0.35, r"\b(enable|enter|activate|switch\s+to)\s+(developer|debug|sudo|admin)\s+mode\b"),
    _r("you_are_now", "role_hijack", 0.65,
       r"\byou\s+are\s+(now|no\s+longer)\b[^.\n]{0,60}\b(ai|assistant|model|chatbot|bound|restricted|unrestricted|unfiltered|jailbroken|evil|free)\b"),
    _r("pretend_unrestricted", "role_hijack", 0.65,
       r"\b(pretend|imagine|act\s+as\s+if)\b[^.\n]{0,40}\b(you\s+are|you're|to\s+be)\b[^.\n]{0,60}\b(no|without|unrestricted|unfiltered|evil|uncensored)\b"),
    _r("no_safety_guidelines", "role_hijack", 0.6,
       r"\b(without|no|ignore|free\s+of)\s+(any\s+)?(ethical|moral|safety|content)\s+(guidelines|restrictions|filters|limits|constraints|policies)\b"),
    # --- system prompt extraction -------------------------------------------
    _r("reveal_system_prompt", "prompt_extraction", 0.8,
       r"\b(reveal|print|show|repeat|output|display|tell\s+me|leak|dump|recite|disclose|share|give\s+me)\b[^.\n]{0,40}"
       r"\b(your|the)\s+(full\s+|exact\s+|complete\s+)?(system\s+prompt|system\s+message|initial\s+(prompt|instructions)|"
       r"hidden\s+(prompt|instructions)|original\s+instructions|pre-?prompt|instructions\s+above)\b"),
    _r("repeat_text_above", "prompt_extraction", 0.6,
       r"\b(repeat|print|output|copy)\b[^.\n]{0,30}\b(everything|all|text|words)\b[^.\n]{0,25}\babove\b"),
    _r("what_are_your_instructions", "prompt_extraction", 0.55,
       r"\bwhat\s+(were|are)\s+your\s+(initial\s+|original\s+|system\s+|exact\s+)?(instructions|rules)\b"),
    # --- delimiter / chat-template injection ---------------------------------
    _r("chat_template_token", "delimiter_injection", 0.9,
       r"<\|(im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id)\|>"),
    _r("llama_inst_tags", "delimiter_injection", 0.8, r"\[/?INST\]|<</?SYS>>"),
    _r("xml_role_tag", "delimiter_injection", 0.6, r"</?\s*(system|system_prompt|instructions?|admin)\s*>"),
    _r("markdown_role_header", "delimiter_injection", 0.5,
       r"^\s*#{1,6}\s*(system|admin|developer)\s*(prompt|message|instructions?|override)?\s*:?\s*$"),
    _r("fake_turn_marker", "delimiter_injection", 0.3, r"^\s*(system|assistant)\s*:\s*\S"),
    # --- data exfiltration ----------------------------------------------------
    _r("markdown_image_with_data", "data_exfiltration", 0.9,
       r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*(\{|\$|<|\[|%7B|data|secret|token|key|conv|chat|history|session|pass)[^)]*\)"),
    _r("markdown_image_query", "data_exfiltration", 0.5, r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*=[^)]*\)"),
    _r("send_data_to_endpoint", "data_exfiltration", 0.85,
       r"\b(send|post|upload|forward|transmit|exfiltrate|leak|email|submit)\b[^.\n]{0,60}"
       r"\b(conversation|chat\s+history|previous\s+messages|passwords?|credentials?|api[\s_-]?keys?|secrets?|tokens?|"
       r"personal\s+data|user'?s?\s+(data|messages|emails|files))\b[^.\n]{0,60}\b(to|at|via)\b[^.\n]{0,40}(https?://|\b\S+@\S+\.\w+|webhook)"),
    _r("encode_into_url", "data_exfiltration", 0.7,
       r"\b(append|include|encode|embed|put)\b[^.\n]{0,60}\b(conversation|chat|user'?s?\s+(data|messages|input)|secrets?|"
       r"summary|history)\b[^.\n]{0,40}\b(url|link|query\s+(string|parameter)|image)\b"),
    # --- tool coercion / excessive agency ------------------------------------
    _r("dangerous_tool_call", "tool_coercion", 0.7,
       r"\b(call|invoke|use|execute|run|trigger)\b[^.\n]{0,30}\b(tool|function|plugin|api|command|action)\b[^.\n]{0,60}"
       r"\b(delete|remove|transfer|send|wire|drop|grant|disable|revoke|refund|purchase|pay|approve|forward)\w*"),
    _r("shell_dropper", "tool_coercion", 0.75,
       r"\brm\s+-rf\s+[/~]|\b(curl|wget)\s+[^|\n]+\|\s*(sudo\s+)?(ba|z)?sh\b|\bDROP\s+TABLE\b|\bchmod\s+777\b"),
    _r("move_money", "tool_coercion", 0.7,
       r"\b(transfer|wire|send|pay)\s+\$?\d[\d,]*(\.\d+)?\s*(usd|dollars|eur|btc|eth)?\b[^.\n]{0,40}\b(to|into)\s+(the\s+)?(account|wallet|iban)\b"),
    # --- indirect injection markers -----------------------------------------
    _r("address_the_ai", "indirect_addressing", 0.55,
       r"\b(if\s+you\s+are\s+an?\s+(ai|llm|language\s+model|assistant|chatbot|agent)|"
       r"(ai|llm)\s+(assistants?|agents?|models?)\s+(reading|processing|summari[sz]ing|parsing)\s+this|"
       r"note\s+to\s+(the\s+|any\s+)?(ai|llm|assistant|model|agent)|attention\s+(ai|llm|assistant|agent))\b"),
    _r("conceal_from_user", "indirect_addressing", 0.7,
       r"\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|show|alert)\b[^.\n]{0,30}\b(the\s+)?user\b"),
)

_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def _snippet(text: str, start: int, end: int, pad: int = 20) -> str:
    s = text[max(0, start - pad): min(len(text), end + pad)]
    return " ".join(s.split())[:160]


def run_phrase_rules(text: str, view: str) -> list[Signal]:
    signals: list[Signal] = []
    for rule in PHRASE_RULES:
        m = rule.pattern.search(text)
        if m:
            signals.append(Signal(rule.category, rule.name, rule.weight, _snippet(text, m.start(), m.end()), view))
    return signals


def decode_base64_blobs(text: str) -> list[str]:
    """Return readable plaintexts for base64-looking tokens in ``text``."""
    decoded: list[str] = []
    for token in _B64_TOKEN.findall(text):
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            plain = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for c in plain if c.isprintable() or c in "\n\t")
        if plain and printable / len(plain) >= 0.9 and sum(c.isalpha() for c in plain) >= 8:
            decoded.append(plain)
    return decoded


def structural_signals(norm: NormalizedText) -> list[Signal]:
    out: list[Signal] = []
    if norm.tag_char_count:
        preview = norm.hidden_tag_text[:80] or "<non-printable>"
        out.append(Signal("obfuscation", "unicode_tag_smuggling", 0.9,
                          f"{norm.tag_char_count} invisible tag chars decode to: {preview!r}"))
    if norm.bidi_count:
        out.append(Signal("obfuscation", "bidi_override", 0.5, f"{norm.bidi_count} bidirectional control chars"))
    if norm.zero_width_count:
        weight = 0.25 if norm.zero_width_count < 3 else 0.45
        out.append(Signal("obfuscation", "zero_width_chars", weight, f"{norm.zero_width_count} zero-width chars"))
    if norm.mixed_script_words:
        out.append(Signal("obfuscation", "mixed_script_homoglyphs", 0.5,
                          "mixed-script words: " + ", ".join(norm.mixed_script_words[:5])))
    return out


def detect(norm: NormalizedText) -> list[Signal]:
    """Run every detector across every view of the text and de-duplicate."""
    signals = structural_signals(norm)
    signals += run_phrase_rules(norm.text, "text")
    if norm.despaced != norm.text:
        direct = {s.rule for s in signals}
        spaced_only = [s for s in run_phrase_rules(norm.despaced, "despaced") if s.rule not in direct]
        if spaced_only:
            signals.append(Signal("obfuscation", "letter_spacing", 0.4,
                                  f"trigger phrase only matches after removing letter-spacing: {spaced_only[0].evidence!r}",
                                  "despaced"))
        signals += spaced_only
    if norm.hidden_tag_text:
        signals += run_phrase_rules(norm.hidden_tag_text, "unicode_tags")

    for plain in decode_base64_blobs(norm.text):
        nested = run_phrase_rules(plain, "base64")
        if nested:
            worst = max(nested, key=lambda s: s.weight)
            signals.append(Signal("encoded_payload", "base64_injection", 0.9,
                                  f"base64 decodes to {worst.category}: {worst.evidence!r}", "base64"))
            signals += nested

    # Keep the first hit per rule: views are ordered most-direct first.
    seen: set[str] = set()
    unique: list[Signal] = []
    for s in signals:
        if s.rule not in seen:
            seen.add(s.rule)
            unique.append(s)
    return unique
