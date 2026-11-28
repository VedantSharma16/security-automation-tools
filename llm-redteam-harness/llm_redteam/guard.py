"""A transparent, heuristic prompt-injection guard.

This is the blue-team half of the project. It scores untrusted text (user
input or retrieved documents) by combining weighted, explainable signals with
a noisy-OR:  score = 1 - prod(1 - w_i).  Every verdict lists the signals that
fired, so an analyst can see *why* something was blocked.

It is intentionally simple and is evaluated honestly against the attack and
benign corpora (see ``evaluate``) – the point is a measurable baseline, not a
claim that regexes solve prompt injection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from llm_redteam.textutils import ZERO_WIDTH, decode_base64_blobs, normalize

DEFAULT_THRESHOLD = 0.5


@dataclass(frozen=True)
class Signal:
    name: str
    weight: float
    pattern: re.Pattern
    description: str


def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


SIGNALS: tuple[Signal, ...] = (
    Signal("instruction_override", 0.65,
           _rx(r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|preceding|all|your|the)\b[^.\n]{0,25}\b(instructions?|rules|directions|guidelines|task|prompt|policy|polic(?:y|ies)|confidentiality)\b"),
           "attempts to cancel or override prior instructions"),
    Signal("new_instructions", 0.4,
           _rx(r"\b(new|updated|revised)\s+(instructions?|policy|rules|directive)\b|\bfrom now on\b|\bactually,?\s+(disregard|ignore|instead)\b"),
           "introduces replacement instructions"),
    Signal("role_spoofing", 0.45,
           _rx(r"^\s*(system|admin|developer|assistant)\s*:|</?\s*(system|user_query|instructions?)\s*>|\[(system|inst)\]|<\|im_start\|>|\bdeveloper override\b"),
           "spoofs a privileged role or chat-template delimiter"),
    Signal("prompt_extraction", 0.55,
           _rx(r"\b(repeat|print|reveal|show|output|dump|summari[sz]e|what are)\b[^.\n]{0,40}\b(system prompt|initial instructions|instructions above|everything above|rules you were given|your instructions|hidden prompt)\b"),
           "tries to extract the system prompt"),
    Signal("jailbreak_persona", 0.5,
           _rx(r"\b(DAN|do anything now|developer mode|jailbreak|no (content )?polic(y|ies)|no restrictions|unfiltered|stay in character)\b"),
           "unrestricted-persona jailbreak language"),
    Signal("secret_seeking", 0.3,
           _rx(r"\b(api[ _-]?key|secret|password|credential|access token|private key)s?\b"),
           "asks about secrets or credentials"),
    Signal("encoding_evasion", 0.3,
           _rx(r"\b(base64|backwards|reversed?|rot13|hex(adecimal)?|spell (it )?out|between each character)\b"),
           "requests an encoding commonly used to slip past output filters"),
    Signal("exfil_markup", 0.6,
           _rx(r"!\[[^\]]*\]\(https?://[^)]*\?[^)]*=|\b(append|include|end your answer with)\b[^.\n]{0,40}\b(image|url|link)\b"),
           "markdown image/link that could carry data to an external host"),
    Signal("ai_addressed", 0.35,
           _rx(r"\b(note to|attention|instructions? for)\s+(the\s+)?(ai|assistant|llm|language model|chatbot)s?\b|\bai (assistant|systems?)\s*:"),
           "text addressed to an AI system (typical of indirect injection)"),
    Signal("output_forcing", 0.25,
           _rx(r"\b(reply|respond|answer|output|say)\b[^.\n]{0,30}\b(only|exactly|nothing else)\b|\bconfirm by saying\b"),
           "forces a specific verbatim output"),
)


@dataclass
class GuardResult:
    score: float
    blocked: bool
    signals: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"score": round(self.score, 3), "blocked": self.blocked, "signals": self.signals, "notes": self.notes}


class InjectionGuard:
    def __init__(self, threshold: float = DEFAULT_THRESHOLD, use_normalization: bool = True):
        if not 0.0 < threshold <= 1.0:
            raise ValueError("threshold must be in (0, 1]")
        self.threshold = threshold
        self.use_normalization = use_normalization

    def scan(self, text: str) -> GuardResult:
        notes: list[str] = []
        extra_weights: list[float] = []

        if self.use_normalization:
            if any(ch in text for ch in ZERO_WIDTH):
                notes.append("zero-width characters removed")
                extra_weights.append(0.2)
            if any(ord(ch) > 0x2FF for ch in text if ch.isalpha()) and re.search(r"[A-Za-z]", text):
                notes.append("mixed-script text (possible homoglyphs) folded to Latin")
            if decode_base64_blobs(text):
                notes.append("embedded base64 decoded and scanned")
            haystack = normalize(text)
        else:
            haystack = text

        fired = [s for s in SIGNALS if s.pattern.search(haystack)]
        weights = [s.weight for s in fired] + extra_weights

        remaining = 1.0
        for w in weights:
            remaining *= 1.0 - w
        score = 1.0 - remaining

        return GuardResult(score=score, blocked=score >= self.threshold,
                           signals=[s.name for s in fired], notes=notes)


@dataclass
class GuardMetrics:
    threshold: float
    normalization: bool
    tp: int
    fp: int
    tn: int
    fn: int
    false_negatives: list[str]
    false_positives: list[str]

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    def to_dict(self) -> dict:
        return {
            "threshold": self.threshold,
            "normalization": self.normalization,
            "confusion": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
        }


def evaluate(guard: InjectionGuard, malicious: dict[str, str], benign: list[str]) -> GuardMetrics:
    """Score the guard on labelled data. ``malicious`` maps attack id -> injected text."""
    fn_ids = [aid for aid, text in malicious.items() if not guard.scan(text).blocked]
    fp_texts = [text for text in benign if guard.scan(text).blocked]
    tp = len(malicious) - len(fn_ids)
    fp = len(fp_texts)
    return GuardMetrics(
        threshold=guard.threshold, normalization=guard.use_normalization,
        tp=tp, fp=fp, tn=len(benign) - fp, fn=len(fn_ids),
        false_negatives=fn_ids, false_positives=fp_texts,
    )
