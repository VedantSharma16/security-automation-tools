"""Merges specialist tool outputs into a single incident verdict.

Each specialist tool has its own severity vocabulary and finding shape; this
module normalizes across them and produces one report an analyst (or a
downstream system) can act on: an overall severity, a 0-100 risk score, the
union of MITRE ATT&CK techniques touched, and a recommended-actions list
derived from which finding types actually fired -- not generic boilerplate.
"""

from __future__ import annotations

from dataclasses import dataclass

from .tools import ToolResult

_SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]
_RISK_WEIGHT = {"low": 10, "medium": 25, "high": 45, "critical": 70}

_RECOMMENDATION_RULES = [
    (
        lambda types: "brute_force" in types or "compromise_after_brute_force" in types,
        "Rotate credentials for the targeted account(s) and rate-limit or block the source IP.",
    ),
    (
        lambda types: "privilege_escalation" in types,
        "Review sudo/privilege-escalation activity for legitimacy; revoke unexpected root access.",
    ),
    (
        lambda types: "persistence_root_account" in types or "persistence_crontab" in types,
        "Audit local accounts and cron/scheduled tasks for unauthorized persistence and remove "
        "any found.",
    ),
]


def _normalize_severity(value: str | None) -> str:
    if not value:
        return "none"
    value = value.lower()
    return value if value in _SEVERITY_ORDER else "none"


def _overall_severity(tool_results: list[ToolResult]) -> str:
    best = "none"
    for result in tool_results:
        if not result.ok:
            continue
        sev = _normalize_severity(result.severity)
        if _SEVERITY_ORDER.index(sev) > _SEVERITY_ORDER.index(best):
            best = sev
    return best


def _risk_score(tool_results: list[ToolResult]) -> int:
    score = sum(
        _RISK_WEIGHT.get(_normalize_severity(r.severity), 0) for r in tool_results if r.ok
    )
    return min(100, score)


def _collect_mitre_techniques(tool_results: list[ToolResult]) -> list[dict]:
    seen: dict[str, dict] = {}
    for result in tool_results:
        if not result.ok:
            continue
        if result.tool == "run_process_hunt":
            for f in result.data.get("findings", []):
                key = f["mitre_technique"]
                seen.setdefault(
                    key,
                    {"id": key, "tactic": f["mitre_tactic"], "source": "run_process_hunt"},
                )
        if result.tool == "run_ioc_triage":
            for t in result.data.get("matched_techniques", []):
                key = t["id"]
                seen.setdefault(
                    key,
                    {
                        "id": key,
                        "tactic": t["tactic"],
                        "name": t.get("name"),
                        "source": "run_ioc_triage",
                    },
                )
    return list(seen.values())


def _recommended_actions(tool_results: list[ToolResult]) -> list[str]:
    finding_types: set[str] = set()
    for result in tool_results:
        if result.tool == "run_log_triage" and result.ok:
            finding_types.update(f["type"] for f in result.data.get("findings", []))

    actions = [message for predicate, message in _RECOMMENDATION_RULES if predicate(finding_types)]

    for result in tool_results:
        if result.tool == "run_ioc_triage" and result.ok:
            hits = {e["value"] for e in result.data.get("enrichment", []) if e["is_known_malicious"]}
            if hits:
                actions.append(
                    "Block/monitor the following known-malicious indicators and hunt for "
                    "related activity across the environment: " + ", ".join(sorted(hits))
                )
        if result.tool == "run_process_hunt" and result.ok and result.data.get("finding_count"):
            actions.append(
                "Isolate this host from the network pending review -- active suspicious "
                "processes were found."
            )

    if not actions:
        actions.append("No immediate action required based on current evidence; continue routine monitoring.")
    return actions


def build_narrative(tool_results: list[ToolResult], overall_severity: str) -> str:
    """Deterministic, offline analyst narrative built directly from tool summaries."""
    ran = [r for r in tool_results if r.ok]
    failed = [r for r in tool_results if not r.ok]

    lines = [f"Incident severity: {overall_severity.upper()}.", ""]
    if not ran:
        lines.append("No specialist tool produced usable output for this case.")
    else:
        for r in ran:
            lines.append(f"- {r.tool}: {r.summary}")
    if failed:
        lines.append("")
        for r in failed:
            lines.append(f"- {r.tool} could not run: {r.error}")
    return "\n".join(lines)


@dataclass
class InvestigationReport:
    case_dir: str
    incident_description: str
    tools_invoked: list[ToolResult]
    overall_severity: str
    risk_score: int
    mitre_techniques: list[dict]
    recommended_actions: list[str]
    narrative: str
    llm_backed: bool
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "case_dir": self.case_dir,
            "incident_description": self.incident_description,
            "tools_invoked": [t.to_dict() for t in self.tools_invoked],
            "overall_severity": self.overall_severity,
            "risk_score": self.risk_score,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "narrative": self.narrative,
            "llm_backed": self.llm_backed,
            "generated_at": self.generated_at,
        }


def synthesize(
    case,
    tool_results: list[ToolResult],
    narrative: str | None,
    llm_backed: bool,
    generated_at: str,
) -> InvestigationReport:
    overall_severity = _overall_severity(tool_results)
    if not narrative:
        narrative = build_narrative(tool_results, overall_severity)
    return InvestigationReport(
        case_dir=str(case.case_dir),
        incident_description=case.incident_description,
        tools_invoked=tool_results,
        overall_severity=overall_severity,
        risk_score=_risk_score(tool_results),
        mitre_techniques=_collect_mitre_techniques(tool_results),
        recommended_actions=_recommended_actions(tool_results),
        narrative=narrative,
        llm_backed=llm_backed,
        generated_at=generated_at,
    )
