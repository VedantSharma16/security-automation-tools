"""Detectors: prompt injection (inbound) and DLP / leakage (outbound)."""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse

from .findings import Finding, snippet
from .normalize import NormalizedText, normalize
from .rules import INJECTION_RULES, Rule

# --------------------------------------------------------------------------
# Inbound: prompt injection
# --------------------------------------------------------------------------


class InjectionDetector:
    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules if rules is not None else INJECTION_RULES

    def _match_rules(self, text: str, context: str, prefix: str = "", boost: float = 0.0) -> list[Finding]:
        findings = []
        for rule in self.rules:
            match = rule.pattern.search(text)
            if not match:
                continue
            weight = min(0.97, rule.weight_for(context) + boost)
            description = rule.description
            if prefix:
                description = f"{description} (hidden via {prefix.rstrip(':')})"
            elif _is_quoted_mention(text, match.start(), match.end()):
                # "Write a rule that detects 'ignore previous instructions'" is
                # a mention, not a use. Dampen (never zero) — still flaggable.
                weight *= 0.5
                description += " (inside quotes — likely a mention; weight halved)"
            findings.append(Finding(
                rule_id=prefix + rule.rule_id,
                category="prompt_injection",
                weight=round(weight, 3),
                owasp=rule.owasp,
                description=description,
                evidence=snippet(text, match.start(), match.end()),
            ))
        return findings

    def scan(self, text: str, context: str = "input") -> tuple[list[Finding], NormalizedText]:
        norm = normalize(text)
        findings = self._match_rules(norm.text, context)

        # Obfuscation signals. Evasion effort is evidence of intent, so these
        # also boost any rule that matches inside the hidden content.
        if norm.in_word_invisible:
            findings.append(Finding("obf.zero_width_in_word", "obfuscation", 0.35, "LLM01",
                                    f"{norm.in_word_invisible} zero-width character(s) splitting words"))
        if norm.bidi_controls:
            findings.append(Finding("obf.bidi_control", "obfuscation", 0.4, "LLM01",
                                    f"{norm.bidi_controls} bidirectional override character(s)"))
        if norm.smuggled.strip():
            findings.append(Finding("obf.unicode_tag_smuggling", "obfuscation", 0.6, "LLM01",
                                    "Invisible Unicode tag characters encode hidden text",
                                    evidence=norm.smuggled[:80]))
        if norm.mixed_script_words:
            findings.append(Finding("obf.mixed_script_homoglyph", "obfuscation", 0.3, "LLM01",
                                    "Words mixing Latin with Cyrillic/Greek look-alike letters",
                                    evidence=", ".join(norm.mixed_script_words[:5])))

        for technique, hidden in norm.hidden_variants:
            findings.extend(self._match_rules(normalize(hidden).text, context, prefix=f"{technique}:", boost=0.1))

        return _dedupe(findings), norm


_QUOTE_PAIRS = {"'": "'", '"': '"', "“": "”", "‘": "’", "`": "`"}


def _is_quoted_mention(text: str, start: int, end: int) -> bool:
    """True if [start, end) sits inside a short quoted span on one line."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    for open_q, close_q in _QUOTE_PAIRS.items():
        left = text.rfind(open_q, line_start, start)
        if left == -1:
            continue
        right = text.find(close_q, end, line_end)
        if right != -1 and (right - left) <= len(text[start:end]) + 40:
            return True
    return False


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.rule_id not in seen or f.weight > seen[f.rule_id].weight:
            seen[f.rule_id] = f
    return list(seen.values())


# --------------------------------------------------------------------------
# Outbound: secrets & PII (DLP) with redaction
# --------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0.9),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|$)"), 0.95),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"), 0.9),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), 0.9),
    ("openai_style_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"), 0.85),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 0.9),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0.75),
]
_ASSIGNED_SECRET = re.compile(
    r"\b(?:api[_-]?key|secret|token|passwd|password|pwd|auth)\b\s*[:=]\s*['\"]?([^\s'\"]{12,})", re.IGNORECASE)

PII_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.3),
    ("us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 0.7),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,19}\b"), 0.75),
]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class SensitiveDataScanner:
    """Finds secrets and PII and produces a redacted copy of the text."""

    def __init__(self, include_pii: bool = True):
        self.include_pii = include_pii

    def _spans(self, text: str) -> list[tuple[int, int, str, str, float]]:
        spans = []
        for name, pattern, weight in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                spans.append((m.start(), m.end(), "secret", name, weight))
        for m in _ASSIGNED_SECRET.finditer(text):
            value = m.group(1)
            if shannon_entropy(value) >= 3.5:
                spans.append((m.start(1), m.end(1), "secret", "high_entropy_assignment", 0.7))
        if self.include_pii:
            for name, pattern, weight in PII_PATTERNS:
                for m in pattern.finditer(text):
                    if name == "credit_card" and not luhn_valid(m.group()):
                        continue
                    spans.append((m.start(), m.end(), "pii", name, weight))
        # Keep the strongest non-overlapping spans.
        spans.sort(key=lambda s: (-s[4], s[0]))
        chosen: list[tuple[int, int, str, str, float]] = []
        for span in spans:
            if all(span[1] <= c[0] or span[0] >= c[1] for c in chosen):
                chosen.append(span)
        return sorted(chosen)

    def scan(self, text: str) -> tuple[list[Finding], str]:
        spans = self._spans(text)
        findings = []
        redacted, cursor = [], 0
        for start, end, category, name, weight in spans:
            owasp = "LLM02"
            findings.append(Finding(f"dlp.{name}", category, weight, owasp,
                                    f"{'Secret' if category == 'secret' else 'PII'} detected: {name}",
                                    evidence=_mask(text[start:end])))
            redacted.append(text[cursor:start])
            redacted.append(f"[REDACTED:{name}]")
            cursor = end
        redacted.append(text[cursor:])
        return _dedupe(findings), "".join(redacted)


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


# --------------------------------------------------------------------------
# Outbound: exfiltration channels in model output
# --------------------------------------------------------------------------

_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)")
_MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*(https?://[^)\s]+)")
_RAW_URL = re.compile(r"https?://[^\s)\]>\"']+")


def domain_allowed(url: str, allowed: tuple[str, ...] | list[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in allowed)


class ExfiltrationScanner:
    """Detects output that would leak data when *rendered* — e.g. a markdown
    image that the chat UI auto-fetches, carrying data in its query string."""

    def __init__(self, allowed_domains: tuple[str, ...] = ()):
        self.allowed_domains = tuple(d.lower() for d in allowed_domains)

    def scan(self, text: str) -> list[Finding]:
        findings = []
        image_urls = set()
        for m in _MD_IMAGE.finditer(text):
            url = m.group(1)
            image_urls.add(url)
            if domain_allowed(url, self.allowed_domains):
                continue
            has_payload = bool(urlparse(url).query) or len(urlparse(url).path) > 60
            weight = 0.85 if has_payload else 0.45
            findings.append(Finding("exfil.markdown_image", "exfiltration", weight, "LLM05",
                                    "Auto-loading image to non-allowlisted domain"
                                    + (" with data in URL" if has_payload else ""), evidence=url[:120]))
        for m in _MD_LINK.finditer(text):
            url = m.group(1)
            if not domain_allowed(url, self.allowed_domains):
                findings.append(Finding("exfil.untrusted_link", "exfiltration", 0.3, "LLM05",
                                        "Link to non-allowlisted domain", evidence=url[:120]))
        for m in _RAW_URL.finditer(text):
            url = m.group()
            if url in image_urls or domain_allowed(url, self.allowed_domains):
                continue
            if len(urlparse(url).query) > 40:
                findings.append(Finding("exfil.long_query_url", "exfiltration", 0.4, "LLM05",
                                        "URL to non-allowlisted domain carrying a long query string",
                                        evidence=url[:120]))
        return _dedupe(findings)


# --------------------------------------------------------------------------
# Outbound: system prompt leakage (canary + verbatim overlap)
# --------------------------------------------------------------------------

def _shingles(text: str, size: int = 8) -> set[tuple[str, ...]]:
    words = re.findall(r"\w+", text.lower())
    return {tuple(words[i:i + size]) for i in range(len(words) - size + 1)}


def detect_prompt_leak(output: str, system_prompt: str | None, canary: str | None) -> list[Finding]:
    findings = []
    if canary and canary in output:
        findings.append(Finding("leak.canary_token", "system_prompt_leak", 1.0, "LLM07",
                                "Canary token from the system prompt appeared in model output",
                                evidence=canary))
    if system_prompt:
        prompt_shingles = _shingles(system_prompt)
        if prompt_shingles:
            overlap = len(prompt_shingles & _shingles(output))
            ratio = overlap / len(prompt_shingles)
            if overlap >= 3 or ratio >= 0.25:
                findings.append(Finding("leak.verbatim_system_prompt", "system_prompt_leak",
                                        0.85 if ratio >= 0.25 else 0.6, "LLM07",
                                        f"Output reproduces {overlap} 8-word span(s) of the system prompt "
                                        f"({ratio:.0%} coverage)"))
    return findings
