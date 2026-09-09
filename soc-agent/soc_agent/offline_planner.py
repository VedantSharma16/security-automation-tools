"""A deterministic, scripted stand-in for the LLM decision-maker.

The live agent (see :mod:`soc_agent.agent`) lets an LLM decide, step by
step, which tool to call next. That loop needs an ``ANTHROPIC_API_KEY`` to
run. So that the whole pipeline — tool dispatch, the step transcript, and
report generation — stays runnable and unit-testable without a key or
network access, this module plays the LLM's role with fixed, inspectable
logic: extract obvious leads from the alert text, investigate each one
with the *same* tool functions the live agent uses, and score severity
from what comes back.

It is deliberately not "smart" — it won't notice a novel attack pattern
it wasn't scripted for. That's the point of the live/offline split: the
offline path proves the harness (tools, transcript, report) is real,
while the live path is where actual reasoning happens.
"""

from __future__ import annotations

import re

from .tools import TOOL_DISPATCH, ToolContext, Verdict

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_USER_RE = re.compile(r"(?:user\s+['\"]?|for\s+)([A-Za-z][A-Za-z0-9_.-]{1,31})(?:['\"]?\s+from\b|['\"])", re.IGNORECASE)
_SUSPICIOUS_PROCESS_HINTS = (
    "mimikatz", "psexec", "certutil", "rundll32", "regsvr32", "powershell",
    "nc.exe", "netcat", "cobaltstrike", "meterpreter",
)


class Step:
    """One recorded (tool, arguments, result) triple in the investigation transcript."""

    __slots__ = ("tool", "arguments", "result")

    def __init__(self, tool: str, arguments: dict, result: dict):
        self.tool = tool
        self.arguments = arguments
        self.result = result

    def to_dict(self) -> dict:
        return {"tool": self.tool, "arguments": self.arguments, "result": self.result}


def _call(ctx: ToolContext, transcript: list[Step], tool: str, **kwargs) -> dict:
    result = TOOL_DISPATCH[tool](ctx, **kwargs)
    transcript.append(Step(tool, kwargs, result))
    return result


def _extract_ips(text: str) -> list[str]:
    seen: list[str] = []
    for match in _IPV4_RE.finditer(text):
        if match.group(0) not in seen:
            seen.append(match.group(0))
    return seen


def _extract_users(text: str) -> list[str]:
    seen: list[str] = []
    for match in _USER_RE.finditer(text):
        user = match.group(1)
        if user.lower() not in (u.lower() for u in seen):
            seen.append(user)
    return seen


def _extract_suspicious_processes(text: str) -> list[str]:
    lowered = text.lower()
    return [hint for hint in _SUSPICIOUS_PROCESS_HINTS if hint in lowered]


def _has_brute_force_then_success(log_lines: list[str]) -> bool:
    failed = any("failed password" in line.lower() for line in log_lines)
    accepted = any("accepted password" in line.lower() for line in log_lines)
    return failed and accepted


def run_offline_investigation(alert_text: str, ctx: ToolContext, max_steps: int = 8) -> tuple[Verdict, list[Step]]:
    """Deterministically investigate ``alert_text`` using ``ctx``'s tools."""
    transcript: list[Step] = []

    ips = _extract_ips(alert_text)
    users = _extract_users(alert_text)
    processes = _extract_suspicious_processes(alert_text)

    reputation_hits = []
    for ip in ips:
        result = _call(ctx, transcript, "check_ioc_reputation", indicator=ip)
        if result["known_malicious"]:
            reputation_hits.append(result)

    matched_ip_logs: list[str] = []
    for ip in ips:
        result = _call(ctx, transcript, "search_logs", query=ip)
        matched_ip_logs.extend(result["matched_lines"])
    for user in users:
        result = _call(ctx, transcript, "search_logs", query=user)
        matched_ip_logs.extend(result["matched_lines"])

    technique_result = _call(ctx, transcript, "lookup_attack_technique", keywords=alert_text)

    baseline_violations = []
    for process in processes:
        result = _call(ctx, transcript, "check_process_baseline", process_name=process)
        if not result["known_good"]:
            baseline_violations.append(process)

    brute_force_signal = _has_brute_force_then_success(matched_ip_logs)
    technique_matches = technique_result["matches"]

    # ATT&CK technique matches are kept as informational context, not a
    # severity driver on their own: a keyword-matched technique like "Valid
    # Accounts" fires just as readily on a routine successful login as on a
    # real compromise, so letting it alone raise severity would make every
    # alert with a login in it "medium". Severity is driven by things that
    # actually indicate anomalous behavior: a known-malicious indicator, a
    # confirmed brute-force pattern in the logs, or a process outside the
    # host's known-good baseline.
    if reputation_hits and brute_force_signal:
        severity = "critical"
    elif reputation_hits or brute_force_signal:
        severity = "high"
    elif baseline_violations:
        severity = "medium"
    else:
        severity = "low"

    key_indicators = list(dict.fromkeys(ips + users + processes))
    matched_technique_labels = [f"{m['id']} {m['name']}" for m in technique_matches]

    summary_parts = []
    if reputation_hits:
        names = ", ".join(f"{h['indicator']} ({h['notes']})" for h in reputation_hits)
        summary_parts.append(f"Known-malicious indicator(s) observed: {names}.")
    if brute_force_signal:
        summary_parts.append("Log evidence shows repeated failed authentication followed by a successful login for the same source, consistent with a successful brute-force attempt.")
    if baseline_violations:
        summary_parts.append(f"Process(es) not present in the host baseline: {', '.join(baseline_violations)}.")
    if technique_matches:
        summary_parts.append(f"Alert language most closely matches: {', '.join(matched_technique_labels)}.")
    if not summary_parts:
        summary_parts.append("No indicators matched local threat intel, no brute-force log pattern was found, and no baseline violations were observed.")
    summary = " ".join(summary_parts)

    recommended_actions = _recommend_actions(severity, ips, users)

    verdict_dict = _call(
        ctx,
        transcript,
        "finish_investigation",
        severity=severity,
        summary=summary,
        key_indicators=key_indicators,
        matched_techniques=matched_technique_labels,
        recommended_actions=recommended_actions,
    )

    if len(transcript) > max_steps:
        raise RuntimeError(f"Offline planner exceeded max_steps={max_steps} ({len(transcript)} tool calls taken)")

    verdict = Verdict(**verdict_dict, steps_taken=len(transcript))
    return verdict, transcript


def _recommend_actions(severity: str, ips: list[str], users: list[str]) -> list[str]:
    if severity == "critical":
        actions = ["Isolate the affected host from the network immediately."]
        if users:
            actions.append(f"Force a password reset and revoke active sessions for: {', '.join(users)}.")
        if ips:
            actions.append(f"Block outbound/inbound traffic to {', '.join(ips)} at the perimeter firewall.")
        actions.append("Escalate to tier-2/IR for full compromise assessment and evidence preservation.")
        return actions
    if severity == "high":
        actions = ["Confirm the scope of access gained and check for lateral movement or new accounts."]
        if users:
            actions.append(f"Require MFA re-enrollment / reset credentials for: {', '.join(users)}.")
        actions.append("Pivot on the flagged indicators across other hosts and the SIEM for related activity.")
        return actions
    if severity == "medium":
        return [
            "Review the flagged process(es) and technique matches with the asset owner.",
            "Add confirmed-benign findings to the local allowlists to reduce future noise.",
        ]
    return ["No immediate action required; log the alert as reviewed and closed."]
