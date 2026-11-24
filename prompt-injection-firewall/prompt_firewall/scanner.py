"""Core scanner: normalise -> match rules -> score -> verdict -> sanitise.

The scanner is *source-aware*. The same sentence means different things
depending on where it came from:

* ``user``        - a direct prompt. Users legitimately give instructions,
                    so only clearly adversarial patterns count.
* ``retrieved``   - a RAG chunk, web page, email or file. Data should never
                    contain instructions for the model, so instruction-like
                    text is scored more aggressively and extra
                    ``indirect_only`` rules switch on.
* ``tool_output`` - the result of an agent tool call; treated like
                    ``retrieved``.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from .normalize import NormalizationResult, normalize, strip_invisible
from .rules import RulePack, load_rules

SOURCES = ("user", "retrieved", "tool_output")
SOURCE_MULTIPLIER = {"user": 1.0, "retrieved": 1.5, "tool_output": 1.5}

ALLOW, SANITIZE, BLOCK = "allow", "sanitize", "block"

EXTERNAL_MD_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(\s*(https?://([^/)\s]+)[^)]*)\)", re.IGNORECASE)
CHAT_TOKEN_RE = re.compile(
    r"<\|[a-z_]+\|>|\[/?INST\]|<</?SYS>>|</?(system|system_prompt|assistant)>", re.IGNORECASE
)


@dataclass
class Policy:
    """Score thresholds. ``score >= block_at`` blocks; ``>= sanitize_at`` sanitises."""

    sanitize_at: int = 30
    block_at: int = 60

    def verdict(self, score: int) -> str:
        if score >= self.block_at:
            return BLOCK
        if score >= self.sanitize_at:
            return SANITIZE
        return ALLOW


@dataclass
class Finding:
    rule_id: str
    name: str
    category: str
    severity: str
    weight: int
    evidence: str
    owasp: str = ""
    atlas: str = ""
    via: str = "text"  # text | base64 | unicode_tags | normalizer


@dataclass
class ScanResult:
    source: str
    score: int
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    sanitized: str | None = None
    judge: dict | None = None

    @property
    def flagged(self) -> bool:
        return self.verdict != ALLOW

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})

    def to_dict(self) -> dict:
        data = asdict(self)
        data["flagged"] = self.flagged
        data["categories"] = self.categories
        return data


def _evidence(match: re.Match, text: str, radius: int = 20) -> str:
    start, end = max(0, match.start() - radius), min(len(text), match.end() + radius)
    snippet = text[start:end].replace("\n", " ").strip()
    return snippet if len(snippet) <= 160 else snippet[:157] + "..."


class Scanner:
    def __init__(self, rules: RulePack | None = None, policy: Policy | None = None, judge=None):
        self.rules = rules or load_rules()
        self.policy = policy or Policy()
        self.judge = judge  # optional LLMJudge for grey-zone escalation

    # ------------------------------------------------------------------ rules
    def _match_rules(self, text: str, source: str, via: str) -> list[Finding]:
        findings = []
        for rule in self.rules.rules:
            if rule.indirect_only and source == "user":
                continue
            match = rule.search(text)
            if match:
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        weight=self.rules.weight(rule.severity),
                        evidence=_evidence(match, text),
                        owasp=rule.owasp,
                        atlas=rule.atlas,
                        via=via,
                    )
                )
        return findings

    def _obfuscation_findings(self, norm: NormalizationResult) -> list[Finding]:
        w = self.rules.weight
        out = []

        def add(rule_id, name, severity, evidence):
            out.append(
                Finding(
                    rule_id=rule_id,
                    name=name,
                    category="obfuscation",
                    severity=severity,
                    weight=w(severity),
                    evidence=evidence,
                    owasp="LLM01:2025 Prompt Injection",
                    atlas="AML.T0068",
                    via="normalizer",
                )
            )

        if norm.tag_payload:
            add("OB-001", "Unicode tag-character smuggling", "critical",
                f"hidden payload: {norm.tag_payload[:120]!r}")
        if norm.zero_width_count:
            sev = "medium" if norm.zero_width_count >= 3 else "low"
            add("OB-002", "Zero-width characters", sev, f"{norm.zero_width_count} invisible character(s)")
        if norm.bidi_count:
            add("OB-003", "Bidirectional override characters", "medium",
                f"{norm.bidi_count} bidi control character(s)")
        if norm.mixed_script_words:
            add("OB-004", "Homoglyph mixed-script words", "medium",
                "words: " + ", ".join(norm.mixed_script_words[:5]))
        return out

    # ------------------------------------------------------------------- scan
    def scan(self, text: str, source: str = "user", sanitize: bool = True) -> ScanResult:
        if source not in SOURCES:
            raise ValueError(f"source must be one of {SOURCES}, got {source!r}")

        norm = normalize(text)
        findings = self._obfuscation_findings(norm)
        findings.extend(self._match_rules(norm.normalized, source, via="text"))
        seen = {f.rule_id for f in findings}

        # Hidden tag-character payloads are scanned as their own text layer.
        if norm.tag_payload:
            hidden = [f for f in self._match_rules(norm.tag_payload, source, via="unicode_tags")
                      if f.rule_id not in seen]
            findings.extend(hidden)
            seen.update(f.rule_id for f in hidden)

        for blob in norm.decoded_blobs:
            nested = [f for f in self._match_rules(blob, source, via="base64") if f.rule_id not in seen]
            if not nested:
                continue
            if "OB-005" not in seen:
                findings.append(
                    Finding(
                        rule_id="OB-005",
                        name="Encoded instructions (base64)",
                        category="obfuscation",
                        severity="high",
                        weight=self.rules.weight("high"),
                        evidence=f"decodes to: {blob[:120]!r}",
                        owasp="LLM01:2025 Prompt Injection",
                        atlas="AML.T0068",
                        via="base64",
                    )
                )
                seen.add("OB-005")
            findings.extend(nested)
            seen.update(f.rule_id for f in nested)

        raw = sum(f.weight for f in findings) * SOURCE_MULTIPLIER[source]
        score = min(100, round(raw))
        result = ScanResult(source=source, score=score, verdict=self.policy.verdict(score), findings=findings)

        # Grey-zone escalation: a confident LLM "injection" verdict raises the
        # outcome by one level. The judge can never *lower* a rule verdict -
        # a model that can be prompt-injected must not be able to unblock.
        if self.judge is not None and result.verdict != BLOCK and score >= self.judge.min_score:
            result.judge = self.judge.classify(text, source=source)
            if result.judge and result.judge.get("label") == "injection" \
                    and result.judge.get("confidence", 0) >= self.judge.escalate_confidence:
                result.verdict = SANITIZE if result.verdict == ALLOW else BLOCK

        if sanitize and result.verdict == SANITIZE:
            result.sanitized = sanitize_text(text, source=source)
        return result


# ---------------------------------------------------------------- sanitising
def neutralize(text: str) -> str:
    """Remove the parts of ``text`` that can act on their own even if the
    model never 'obeys' them: invisible characters, chat-template tokens and
    auto-rendering external images."""
    text = strip_invisible(text)
    text = CHAT_TOKEN_RE.sub("[removed-control-token]", text)
    text = EXTERNAL_MD_IMAGE_RE.sub(lambda m: f"[external image removed: {m.group(3)}]", text)
    return text


def spotlight(text: str, source: str = "retrieved", mode: str = "delimit") -> str:
    """Mark untrusted text so the model can tell data from instructions.

    Implements the two 'spotlighting' variants from Hines et al. (2024),
    *Defending Against Indirect Prompt Injection Attacks With Spotlighting*:

    * ``delimit``  - wrap in explicit untrusted-data tags
    * ``datamark`` - interleave a marker character between every word, so
                     injected instructions no longer read as natural prose
    """
    if mode == "datamark":
        body = "^".join(text.split())
        return (
            f"<untrusted_data source=\"{source}\" encoding=\"datamark:^\">\n{body}\n</untrusted_data>"
        )
    if mode == "delimit":
        safe = text.replace("</untrusted_data>", "</untrusted_data_>")
        return f"<untrusted_data source=\"{source}\">\n{safe}\n</untrusted_data>"
    raise ValueError("mode must be 'delimit' or 'datamark'")


def sanitize_text(text: str, source: str = "retrieved", mode: str = "delimit") -> str:
    neutral = neutralize(text)
    if source == "user":
        return neutral
    return spotlight(neutral, source=source, mode=mode)
