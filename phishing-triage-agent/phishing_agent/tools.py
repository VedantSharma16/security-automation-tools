"""Investigation tools available to the phishing-triage agent.

Each tool is a small, pure function `(ParsedEmail, DataFeeds) -> dict` that
inspects one aspect of the email and returns a JSON-serializable observation.
This is the same shape whether a tool is invoked by the LLM planner (via
Anthropic tool-use) or by the deterministic offline planner — the agent loop
in `agent.py` is the only thing that decides *when* to call them.

Keeping tools as plain functions (rather than methods with hidden state)
means they can be unit-tested directly and reused outside the agent loop.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from phishing_agent import heuristics
from phishing_agent.email_parser import ParsedEmail

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_HEADER_AUTH_RE = re.compile(r"(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)


@dataclass
class DataFeeds:
    trusted_brands: dict[str, str]
    known_malicious_domains: dict[str, str]

    @classmethod
    def load_default(cls) -> "DataFeeds":
        trusted = json.loads((DATA_DIR / "trusted_brands.json").read_text(encoding="utf-8"))
        malicious = json.loads((DATA_DIR / "known_malicious_domains.json").read_text(encoding="utf-8"))
        return cls(trusted_brands=trusted, known_malicious_domains=malicious)


def parse_headers(email: ParsedEmail, feeds: DataFeeds) -> dict:
    mismatch_brand = heuristics.display_name_mismatch(
        email.from_display, email.from_addr, feeds.trusted_brands
    )
    return_path_domain = heuristics.domain_of(email.return_path) if email.return_path else None
    from_domain = heuristics.domain_of(email.from_addr)
    return {
        "from_display": email.from_display,
        "from_addr": email.from_addr,
        "from_domain": from_domain,
        "subject": email.subject,
        "return_path_domain": return_path_domain,
        "return_path_mismatches_from": bool(
            return_path_domain and return_path_domain != from_domain
        ),
        "reply_to": email.reply_to,
        "impersonated_brand": mismatch_brand,
    }


def check_authentication(email: ParsedEmail, feeds: DataFeeds) -> dict:
    raw = email.authentication_results_raw or ""
    results = {key.lower(): value.lower() for key, value in _HEADER_AUTH_RE.findall(raw)}
    return {
        "header_present": bool(raw),
        "spf": results.get("spf", "none"),
        "dkim": results.get("dkim", "none"),
        "dmarc": results.get("dmarc", "none"),
        "all_pass": bool(raw) and all(
            results.get(k) == "pass" for k in ("spf", "dkim", "dmarc")
        ),
        "any_fail": any(results.get(k) == "fail" for k in ("spf", "dkim", "dmarc")),
    }


def extract_urls(email: ParsedEmail, feeds: DataFeeds) -> dict:
    return {"url_count": len(email.urls), "urls": email.urls}


def check_url_reputation(email: ParsedEmail, feeds: DataFeeds) -> dict:
    findings = []
    for url in email.urls:
        domain = heuristics.domain_of(url)
        entry = {"url": url, "domain": domain, "flags": []}

        if domain in feeds.known_malicious_domains:
            entry["flags"].append("known_malicious")
            entry["known_malicious_note"] = feeds.known_malicious_domains[domain]

        typo = heuristics.closest_trusted_brand(domain, feeds.trusted_brands)
        if typo:
            entry["flags"].append("typosquat")
            entry["typosquat_target"] = {"brand": typo[1], "brand_domain": typo[0], "edit_distance": typo[2]}

        if heuristics.is_punycode(domain):
            entry["flags"].append("punycode_homograph")

        if heuristics.is_ip_literal(domain):
            entry["flags"].append("ip_literal_url")

        findings.append(entry)

    return {
        "checked": len(findings),
        "flagged": [f for f in findings if f["flags"]],
        "all": findings,
    }


def check_attachments(email: ParsedEmail, feeds: DataFeeds) -> dict:
    findings = []
    for att in email.attachments:
        flags = heuristics.risky_attachment_flags(att.filename)
        findings.append({
            "filename": att.filename,
            "content_type": att.content_type,
            "size_bytes": att.size_bytes,
            "flags": flags,
        })
    return {
        "attachment_count": len(findings),
        "flagged": [f for f in findings if f["flags"]],
        "all": findings,
    }


def analyze_language(email: ParsedEmail, feeds: DataFeeds) -> dict:
    hits = heuristics.urgency_language_hits(email.body_text)
    return {"urgency_phrase_hits": hits, "hit_count": len(hits)}


# Ordered so the offline planner runs the cheapest / most structural checks
# first — mirrors a reasonable human analyst's triage order.
TOOL_REGISTRY = {
    "parse_headers": parse_headers,
    "check_authentication": check_authentication,
    "extract_urls": extract_urls,
    "check_url_reputation": check_url_reputation,
    "check_attachments": check_attachments,
    "analyze_language": analyze_language,
}

TOOL_ORDER = list(TOOL_REGISTRY.keys())

TOOL_SPECS = [
    {
        "name": "parse_headers",
        "description": (
            "Inspect the From/Return-Path/Reply-To headers for display-name "
            "spoofing, envelope mismatches, and brand impersonation."
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "check_authentication",
        "description": "Read SPF/DKIM/DMARC authentication results for the message.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "extract_urls",
        "description": "List every URL found in the email body.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "check_url_reputation",
        "description": (
            "Check each URL's domain against a known-malicious feed and for "
            "typosquatting/homograph impersonation of trusted brands."
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "check_attachments",
        "description": "Check attachment filenames for risky or double extensions.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "analyze_language",
        "description": "Scan the body text for urgency/social-engineering language.",
        "input_schema": {"type": "object", "properties": {}},
    },
]

SUBMIT_VERDICT_SPEC = {
    "name": "submit_verdict",
    "description": (
        "Submit the final triage verdict once enough tools have been run to "
        "support a conclusion. Call this exactly once, as the last action."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["phishing", "suspicious", "benign"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "reasoning": {"type": "string"},
            "key_evidence": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["verdict", "confidence", "reasoning", "key_evidence"],
    },
}
