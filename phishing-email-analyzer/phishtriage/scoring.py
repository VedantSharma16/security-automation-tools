"""Correlate indicators into higher-confidence findings, then score and classify.

Individual weak signals (a Return-Path mismatch, an urgent tone) are common in
legitimate mail. What separates phishing is *combinations*, so a small set of
correlation rules promotes co-occurring signals into a single, explicit
finding. The final score is a capped sum of severity weights, and the verdict
also respects a severity floor so one critical indicator can't be diluted.
"""

from __future__ import annotations

from dataclasses import dataclass

from .indicators import SEVERITY_ORDER, Indicator

VERDICTS = [  # (min score, label)
    (70, "malicious"),
    (40, "likely-phishing"),
    (15, "suspicious"),
    (0, "benign"),
]


def _ids(indicators: list[Indicator]) -> set[str]:
    return {i.id for i in indicators}


def correlate(indicators: list[Indicator]) -> list[Indicator]:
    """Return additional correlated indicators derived from combinations."""
    ids = _ids(indicators)
    auth_fail = bool(ids & {"spf_fail", "dmarc_fail", "spf_softfail", "dkim_fail"})
    impersonation = bool(ids & {"sender_lookalike_domain", "display_name_brand_spoof",
                                "display_name_embedded_address"})
    bad_link = bool(ids & {"url_lookalike_domain", "url_text_mismatch", "url_ip_host",
                           "url_userinfo_obfuscation", "url_free_hosting", "html_form_post"})
    out: list[Indicator] = []

    if "content_credential_request" in ids and bad_link:
        out.append(Indicator(
            "corr_credential_harvest", "correlation", "critical",
            "Credential-harvesting pattern",
            "A sign-in/verification lure is paired with a deceptive or high-risk link.",
            mitre=["T1598.003", "T1566.002"]))
    has_payload = any(i.category == "attachment" for i in indicators) or bad_link
    # BEC is payload-less social engineering; with a malicious link/attachment the
    # payload findings already describe the attack better.
    if "content_bec_language" in ids and not has_payload and (
            "reply_to_mismatch" in ids or impersonation):
        out.append(Indicator(
            "corr_bec", "correlation", "high",
            "Business-email-compromise pattern",
            "Payment language combined with reply diversion or sender impersonation.",
            mitre=["T1656"]))
    if impersonation and auth_fail:
        out.append(Indicator(
            "corr_spoofed_sender", "correlation", "high",
            "Impersonated sender failed authentication",
            "The sender claims a trusted identity and the receiving server could not verify it.",
            mitre=["T1656"]))
    return out


@dataclass
class Assessment:
    score: int
    verdict: str
    highest_severity: str
    indicators: list[Indicator]


def assess(indicators: list[Indicator]) -> Assessment:
    all_ind = indicators + correlate(indicators)
    all_ind.sort(key=lambda i: SEVERITY_ORDER.index(i.severity), reverse=True)

    score = min(100, sum(i.weight for i in all_ind))
    highest = all_ind[0].severity if all_ind else "info"

    verdict = next(label for threshold, label in VERDICTS if score >= threshold)
    # Severity floor: a single critical/high indicator can't be scored as benign.
    floor = {"critical": "likely-phishing", "high": "suspicious"}.get(highest)
    labels = [label for _, label in reversed(VERDICTS)]  # benign .. malicious
    if floor and labels.index(verdict) < labels.index(floor):
        verdict = floor
    return Assessment(score=score, verdict=verdict, highest_severity=highest, indicators=all_ind)
