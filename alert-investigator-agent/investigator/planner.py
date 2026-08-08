"""Deterministic, offline "ReAct-style" investigation loop.

No LLM involved: this module *is* the agent when no API key is configured
(or as the safety fallback when the live LLM agent misbehaves). It still
behaves agentically rather than as a fixed pipeline — later tool calls are
chosen based on what earlier ones returned, and low-value lookups are
skipped to conserve investigation effort, exactly the branching a human
analyst (or an LLM given the same tools) would do.

Decision order:
  1. Check indicator reputation for every indicator on the alert.
  2. Always check the asset's blast radius (criticality/owner/environment).
  3. Only pull alert history if there's a malicious hit *or* the asset is
     high/critical — a clean indicator on a low-value box isn't worth it.
  4. Always map the alert narrative to a MITRE technique (cheap, useful).
  5. Score the aggregated signals and render a verdict.
"""

from __future__ import annotations

from investigator import tools
from investigator.state import Alert, InvestigationResult, ToolCall


def _decide(risk: dict, signals: dict) -> tuple[str, str]:
    """Map risk score + signals to a (verdict, confidence) pair."""
    band = risk["band"]
    malicious = signals.get("any_known_malicious", False)
    recurring_tp = signals.get("recurring_true_positive", False)
    benign_only = signals.get("seen_before_as_benign_only", False)
    technique = signals.get("technique_matched", False)
    asset_known = signals.get("asset_criticality", "unknown") != "unknown"
    criticality = signals.get("asset_criticality")

    if malicious and (criticality in ("high", "critical") or recurring_tp):
        return "true_positive", "high"
    if malicious:
        return "needs_escalation", "medium"
    if benign_only and not technique:
        return "false_positive", "high" if asset_known else "medium"
    if technique and band in ("medium", "high", "critical"):
        return "needs_escalation", "medium"
    if band == "low":
        return "false_positive", "medium" if asset_known else "low"
    return "needs_escalation", "low"


def _build_summary(alert: Alert, signals: dict, verdict: str, risk: dict) -> str:
    parts = [f"Investigated alert {alert.alert_id!r} (risk {risk['score']}/100, {risk['band']})."]
    if signals.get("any_known_malicious"):
        parts.append("At least one indicator matched the local threat-intel feed as known-malicious.")
    else:
        parts.append("No indicator matched the local threat-intel feed.")
    if signals.get("asset_criticality", "unknown") != "unknown":
        parts.append(f"Affected asset criticality: {signals['asset_criticality']}.")
    else:
        parts.append("Affected host was not found in the asset inventory.")
    if signals.get("recurring_true_positive"):
        parts.append("This indicator has a prior true-positive history.")
    elif signals.get("seen_before_as_benign_only"):
        parts.append("This indicator has only ever been closed as false-positive before.")
    if signals.get("technique_matched"):
        parts.append("Alert narrative matches a known ATT&CK technique.")
    parts.append(f"Verdict: {verdict.replace('_', ' ')}.")
    return " ".join(parts)


def _build_actions(verdict: str, technique_match: dict) -> list[str]:
    actions: list[str] = []
    if technique_match.get("matched"):
        actions.extend(technique_match["techniques"][0]["recommended_actions"])

    if verdict == "true_positive":
        actions.append("Escalate to incident response and begin containment immediately.")
    elif verdict == "needs_escalation":
        actions.append("Escalate to a senior analyst for manual review — evidence is suggestive but not conclusive.")
    else:
        actions.append("Document as false positive and close; no further action needed unless recurrence is observed.")

    # de-dupe while preserving order
    seen = set()
    deduped = []
    for action in actions:
        if action not in seen:
            seen.add(action)
            deduped.append(action)
    return deduped


def run(alert: Alert, data_dir=None) -> InvestigationResult:
    """Run the deterministic offline investigation loop over ``alert``."""
    trace: list[ToolCall] = []
    signals: dict = {}

    # Step 1: reputation lookup for every indicator on the alert.
    malicious_hits = []
    confidences = []
    for indicator in alert.indicators:
        output = tools.lookup_indicator_reputation(indicator, data_dir)
        trace.append(
            ToolCall(
                tool="lookup_indicator_reputation",
                input={"indicator": indicator},
                output=output,
                reasoning=f"New indicator {indicator!r} on the alert — checking local threat-intel feed first.",
            )
        )
        if output["is_known_malicious"]:
            malicious_hits.append(output)
            confidences.append(output["confidence"])

    signals["any_known_malicious"] = bool(malicious_hits)
    signals["max_confidence"] = max(confidences, key=lambda c: ["low", "medium", "high"].index(c)) if confidences else None

    # Step 2: asset context — always checked, blast radius shapes everything downstream.
    asset = None
    if alert.host:
        asset = tools.get_asset_context(alert.host, data_dir)
        trace.append(
            ToolCall(
                tool="get_asset_context",
                input={"host": alert.host},
                output=asset,
                reasoning=f"Checking blast radius for affected host {alert.host!r} before deciding how deep to dig.",
            )
        )
    signals["asset_criticality"] = asset["criticality"] if asset else "unknown"

    # Step 3: history lookup only when it's worth the effort.
    history_hits = []
    worth_history = bool(malicious_hits) or signals["asset_criticality"] in ("high", "critical")
    if worth_history:
        for indicator in alert.indicators:
            output = tools.search_alert_history(indicator, data_dir)
            trace.append(
                ToolCall(
                    tool="search_alert_history",
                    input={"indicator": indicator},
                    output=output,
                    reasoning="Indicator is malicious or asset is high-value — checking for recurring activity.",
                )
            )
            history_hits.append(output)
    else:
        trace.append(
            ToolCall(
                tool="search_alert_history",
                input={},
                output={"skipped": True},
                reasoning=(
                    "No malicious indicator and asset criticality is low/medium — skipping history "
                    "lookup to conserve investigation effort."
                ),
            )
        )

    signals["recurring_true_positive"] = any(h.get("prior_true_positive_count", 0) > 0 for h in history_hits)
    signals["seen_before_as_benign_only"] = bool(history_hits) and all(
        h.get("prior_alert_count", 0) > 0 and h.get("prior_true_positive_count", 0) == 0 for h in history_hits
    )

    # Step 4: MITRE technique mapping — always run, cheap and informative.
    technique_match = tools.map_mitre_technique(alert.description or alert.raw, data_dir)
    trace.append(
        ToolCall(
            tool="map_mitre_technique",
            input={"text": alert.description or alert.raw},
            output=technique_match,
            reasoning="Matching alert narrative against known ATT&CK technique keywords.",
        )
    )
    signals["technique_matched"] = technique_match["matched"]

    # Step 5: risk scoring.
    risk = tools.calculate_risk_score(signals)
    trace.append(
        ToolCall(
            tool="calculate_risk_score",
            input={"signals": signals},
            output=risk,
            reasoning="All available signals gathered — scoring before rendering a verdict.",
        )
    )

    verdict, confidence = _decide(risk, signals)
    summary = _build_summary(alert, signals, verdict, risk)
    recommended_actions = _build_actions(verdict, technique_match)

    return InvestigationResult(
        alert=alert,
        trace=trace,
        risk_score=risk["score"],
        risk_band=risk["band"],
        verdict=verdict,
        confidence=confidence,
        summary=summary,
        recommended_actions=recommended_actions,
        mode="offline_planner",
    )
