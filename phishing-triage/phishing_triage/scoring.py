"""Combine every analyzer's findings into a single 0-100 score and verdict."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .auth_analysis import AuthResult
from .content_analysis import AttachmentFinding, ContentFindings, SenderFinding
from .url_analysis import UrlFinding

# Multiple malicious links or attachments shouldn't be able to drown out the
# score's ceiling on their own -- cap each category's contribution.
MAX_URL_CONTRIBUTION = 50
MAX_ATTACHMENT_CONTRIBUTION = 40

SUSPICIOUS_THRESHOLD = 25
LIKELY_PHISHING_THRESHOLD = 60


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_PHISHING = "likely_phishing"


@dataclass(frozen=True)
class TriageResult:
    score: int
    verdict: Verdict
    reasons: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict.value,
            "reasons": list(self.reasons),
        }


def _auth_score(auth: AuthResult) -> tuple[int, list[str]]:
    if not auth.header_present:
        return 5, ["no Authentication-Results header present; SPF/DKIM/DMARC status unknown"]

    score = 0
    reasons: list[str] = []
    if auth.spf == "fail":
        score += 15
        reasons.append("SPF check failed for the sending server")
    if auth.dkim == "fail":
        score += 10
        reasons.append("DKIM signature failed verification")
    if auth.dmarc == "fail":
        score += 20
        reasons.append("DMARC alignment failed")
    return score, reasons


def score_email(
    auth: AuthResult,
    url_findings: list[UrlFinding],
    content: ContentFindings,
    sender: SenderFinding,
    attachment_findings: list[AttachmentFinding],
) -> TriageResult:
    reasons: list[str] = []
    score = 0

    auth_score, auth_reasons = _auth_score(auth)
    score += auth_score
    reasons.extend(auth_reasons)

    url_score = min(MAX_URL_CONTRIBUTION, sum(f.weight for f in url_findings))
    score += url_score
    reasons.extend(r for f in url_findings for r in f.reasons)

    score += content.weight
    if content.matched_urgency_phrases:
        reasons.append(
            "urgency/pressure language detected: "
            + ", ".join(content.matched_urgency_phrases[:3])
        )
    if content.matched_sensitive_info_keywords:
        reasons.append(
            "requests sensitive information: "
            + ", ".join(content.matched_sensitive_info_keywords[:3])
        )
    if content.matched_generic_greeting:
        reasons.append(
            f"uses generic greeting {content.matched_generic_greeting!r} instead of a name"
        )

    score += sender.weight
    reasons.extend(sender.reasons)

    attachment_score = min(
        MAX_ATTACHMENT_CONTRIBUTION, sum(f.weight for f in attachment_findings)
    )
    score += attachment_score
    reasons.extend(r for f in attachment_findings for r in f.reasons)

    score = min(100, score)

    if score >= LIKELY_PHISHING_THRESHOLD:
        verdict = Verdict.LIKELY_PHISHING
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.BENIGN

    return TriageResult(score=score, verdict=verdict, reasons=tuple(reasons))
