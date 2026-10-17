"""Core scanner: normalise -> match rules -> structural checks -> score."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .normalize import count_invisible, decode_base64_blobs, decode_tag_chars, normalize
from .rules import RULES

BLOCK_THRESHOLD = 8
REVIEW_THRESHOLD = 3


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: int
    description: str
    evidence: str
    obfuscated: bool = False  # only matched after normalisation/decoding


@dataclass
class ScanResult:
    source: str
    score: int
    verdict: str  # allow | review | block
    findings: list[Finding] = field(default_factory=list)

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})

    def to_dict(self) -> dict:
        return {**asdict(self), "categories": self.categories}


def _match(text: str, obfuscated: bool, seen: set, out: list[Finding]) -> None:
    for rule in RULES:
        m = rule.pattern.search(text)
        if m and rule.id not in seen:
            seen.add(rule.id)
            out.append(Finding(rule.id, rule.category, rule.severity, rule.description,
                               m.group(0).strip()[:120], obfuscated))


def scan(text: str, source: str = "<input>") -> ScanResult:
    findings: list[Finding] = []
    seen: set[str] = set()

    _match(text, False, seen, findings)
    clean = normalize(text)
    _match(clean, clean != text, seen, findings)

    # Hidden payloads: tag-character smuggling and base64 blobs.
    smuggled = decode_tag_chars(text)
    if smuggled:
        findings.append(Finding("PI-100", "obfuscation", 5, "ASCII smuggled via Unicode tag characters",
                                smuggled[:120], True))
        _match(smuggled, True, seen, findings)
    elif count_invisible(text) >= 3:
        findings.append(Finding("PI-101", "obfuscation", 2, "Unusual density of invisible characters",
                                f"{count_invisible(text)} invisible chars", True))
    for blob in decode_base64_blobs(text):
        before = len(findings)
        _match(normalize(blob), True, seen, findings)
        if len(findings) > before:
            findings.append(Finding("PI-102", "obfuscation", 3, "Injection payload hidden in base64",
                                    blob[:120], True))

    score = sum(f.severity for f in findings)
    # Multiple distinct categories is stronger evidence than one noisy rule.
    cats = {f.category for f in findings}
    if len(cats) >= 3:
        score += 3
    verdict = "block" if score >= BLOCK_THRESHOLD else "review" if score >= REVIEW_THRESHOLD else "allow"
    return ScanResult(source, score, verdict, findings)
