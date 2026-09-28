"""Header-level phishing heuristics: authentication results, sender/reply-to
mismatches, and brand impersonation in the display name.

These are the checks a human analyst does first when triaging a reported
email -- before ever looking at links or attachments -- because a failed
DMARC/SPF/DKIM result or a spoofed display name is strong, cheap signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .urls import COMMON_BRAND_DOMAINS, _levenshtein

AUTH_RESULT_RE = re.compile(r"(?i)\b(spf|dkim|dmarc)\s*=\s*([a-z]+)")


@dataclass
class AuthResults:
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None

    def any_failed(self) -> bool:
        return any(v in {"fail", "softfail"} for v in (self.spf, self.dkim, self.dmarc) if v)

    def none_present(self) -> bool:
        return self.spf is None and self.dkim is None and self.dmarc is None


def parse_auth_results(raw: str) -> AuthResults:
    """Parse an Authentication-Results header into per-mechanism verdicts.

    Only the FIRST spf=/dkim=/dmarc= token is used, matching how mail clients
    typically report the border MTA's own verdict (later tokens can belong to
    other authserv-ids chained in the same header in more complex deployments).
    """
    results = AuthResults()
    for mechanism, verdict in AUTH_RESULT_RE.findall(raw or ""):
        mechanism = mechanism.lower()
        verdict = verdict.lower()
        if mechanism == "spf" and results.spf is None:
            results.spf = verdict
        elif mechanism == "dkim" and results.dkim is None:
            results.dkim = verdict
        elif mechanism == "dmarc" and results.dmarc is None:
            results.dmarc = verdict
    return results


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if addr and "@" in addr else ""


def display_name_impersonation(
    from_display: str, from_addr: str, brands: list[str] = COMMON_BRAND_DOMAINS
) -> str | None:
    """Return the brand a display name claims to be from, when the From address's
    domain doesn't belong to that brand -- e.g. 'PayPal Support' <security@paypa1-verify.com>."""
    if not from_display:
        return None
    display_lower = from_display.lower()
    from_domain = domain_of(from_addr)

    for brand_domain in brands:
        if from_domain == brand_domain or from_domain.endswith("." + brand_domain):
            continue  # display name matches an authentic sending domain for that brand
        brand_name = brand_domain.split(".")[0]
        if re.search(rf"\b{re.escape(brand_name)}\b", display_lower):
            return brand_domain
    return None


def reply_to_mismatch(from_addr: str, reply_to_addr: str) -> bool:
    if not reply_to_addr:
        return False
    return domain_of(reply_to_addr) != domain_of(from_addr)


def return_path_mismatch(from_addr: str, return_path_addr: str) -> bool:
    if not return_path_addr:
        return False
    from_domain, rp_domain = domain_of(from_addr), domain_of(return_path_addr)
    if not rp_domain or from_domain == rp_domain:
        return False
    # A close-but-not-equal Return-Path domain (bulk-mail infra with a typo'd
    # or spoofed variant of the sender's own domain) is more suspicious than an
    # unrelated one (common for legitimate ESPs/newsletter platforms).
    return _levenshtein(from_domain, rp_domain) <= 2
