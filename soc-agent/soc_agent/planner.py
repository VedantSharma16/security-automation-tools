"""Deterministic offline planner: a scripted stand-in for the LLM agent loop.

Without an LLM, the agent still needs to run a multi-step investigation
using the exact same tools. This module encodes a fixed, rule-based
investigation strategy — extract indicators, enrich them, corroborate with
MITRE ATT&CK and log evidence, then score a verdict — so
:class:`soc_agent.agent.SocAgent` is fully runnable and testable offline,
with a trace shaped identically to the live tool-calling path.
"""

from __future__ import annotations

from .models import Alert, AgentStep, AgentResult, Verdict
from .tools import (
    extract_indicators,
    ioc_lookup,
    dns_lookup,
    mitre_lookup,
    search_logs,
    get_asset_criticality,
)

# Behavior keywords worth cross-referencing against ATT&CK. Checked against
# the alert's title + description as simple substring matches.
_BEHAVIOR_KEYWORDS = [
    "beacon", "phishing", "credential", "brute force", "scheduled task",
    "exfiltration", "no mfa", "password spray",
]


def run(alert: Alert, max_steps: int = 12) -> AgentResult:
    trace: list[AgentStep] = []
    step_counter = [0]

    def record(tool: str, tool_input: dict, output: dict) -> dict:
        step_counter[0] += 1
        trace.append(AgentStep(step=step_counter[0], tool=tool, input=tool_input, output=output))
        return output

    text_blob = " ".join(
        filter(None, [alert.title, alert.description, alert.destination, alert.source_ip])
    )
    found = extract_indicators(text_blob)
    candidates = list(dict.fromkeys(alert.raw_indicators + found["domains"] + found["ips"]))

    ioc_hits = []
    for indicator in candidates:
        if step_counter[0] >= max_steps:
            break
        result = record("ioc_lookup", {"indicator": indicator}, ioc_lookup(indicator))
        ioc_hits.append(result)

    domains_to_resolve = [h["indicator"] for h in ioc_hits if h.get("type") == "domain" or h["indicator"] in found["domains"]]
    dns_hits = []
    for domain in domains_to_resolve:
        if step_counter[0] >= max_steps:
            break
        dns_hits.append(record("dns_lookup", {"domain": domain}, dns_lookup(domain)))

    lower_text = text_blob.lower()
    mitre_hits = []
    for keyword in _BEHAVIOR_KEYWORDS:
        if step_counter[0] >= max_steps:
            break
        if keyword in lower_text:
            mitre_hits.append(record("mitre_lookup", {"keyword": keyword}, mitre_lookup(keyword)))

    log_query = alert.source_ip or alert.user or alert.hostname
    log_hits = None
    if log_query and step_counter[0] < max_steps:
        log_hits = record("search_logs", {"query": log_query}, search_logs(log_query))

    asset_hit = None
    if alert.hostname and step_counter[0] < max_steps:
        asset_hit = record("get_asset_criticality", {"hostname": alert.hostname}, get_asset_criticality(alert.hostname))

    verdict = _score(ioc_hits, dns_hits, mitre_hits, log_hits, asset_hit)
    return AgentResult(alert=alert, trace=trace, verdict=verdict, mode="offline")


def _score(ioc_hits, dns_hits, mitre_hits, log_hits, asset_hit) -> Verdict:
    malicious = [h for h in ioc_hits if h.get("verdict") == "malicious"]
    suspicious = [h for h in ioc_hits if h.get("verdict") == "suspicious"]
    young_domains = [d for d in dns_hits if d.get("found") and d.get("age_days", 9999) < 45]
    mitre_matched = [m for m in mitre_hits if m["matches"]]
    high_value_asset = bool(asset_hit and asset_hit.get("criticality") in ("high", "critical"))

    score = 3 * len(malicious) + 1 * len(suspicious)
    score += 1 if young_domains else 0
    score += 1 if (mitre_matched and (malicious or suspicious)) else 0
    score += 1 if high_value_asset else 0

    reasons = []
    if malicious:
        reasons.append(f"{len(malicious)} indicator(s) matched known-malicious threat intel")
    if suspicious:
        reasons.append(f"{len(suspicious)} indicator(s) matched suspicious-but-unconfirmed threat intel")
    if young_domains:
        names = ", ".join(d["domain"] for d in young_domains)
        reasons.append(f"newly-registered/privacy-proxied domain(s) involved ({names})")
    if mitre_matched:
        technique_ids = sorted({m["id"] for hit in mitre_matched for m in hit["matches"]})
        reasons.append(f"behavior corroborated by ATT&CK technique(s) {', '.join(technique_ids)}")
    if high_value_asset:
        reasons.append(f"affected asset criticality is {asset_hit['criticality']}")
    if log_hits and log_hits["match_count"]:
        reasons.append(f"{log_hits['match_count']} corroborating log line(s) found")
    if not reasons:
        reasons.append("no threat-intel, DNS, or log evidence corroborated the alert")

    rationale = "; ".join(reasons) + "."

    if score >= 5:
        verdict, confidence = "malicious", min(0.95, 0.75 + 0.05 * score)
        action = "Isolate the affected host, block the indicators at the perimeter, and open a full incident."
    elif score >= 3:
        verdict, confidence = "malicious", 0.75
        action = "Isolate the affected host and escalate to a tier-2 analyst for confirmation."
    elif score >= 1:
        verdict, confidence = "suspicious", 0.55
        action = "Monitor the indicators, pivot in the SIEM for related activity, and re-triage if new evidence appears."
    else:
        verdict, confidence = "benign", 0.6
        action = "No corroborating evidence found; close as a false positive unless new context emerges."

    return Verdict(verdict=verdict, confidence=round(confidence, 2), recommended_action=action, rationale=rationale)
