"""Human-readable output: scan reports, test results and ATT&CK coverage."""

from __future__ import annotations

from collections import defaultdict

from .engine import ScanResult
from .rule import Rule
from .testing import TestReport

__all__ = ["render_scan_markdown", "render_test_text", "attack_coverage", "render_coverage_markdown"]

_TACTIC_ORDER = [
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control", "exfiltration", "impact",
]
_KEY_FIELDS = ("CommandLine", "Image", "ParentImage", "TargetFilename", "DestinationIp", "User")


def _short(value: object, limit: int = 110) -> str:
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _evidence(event: dict) -> str:
    if event.get("DestinationIp"):
        image = str(event.get("Image", "?")).replace("\\", "/").rsplit("/", 1)[-1]
        port = f":{event['DestinationPort']}" if event.get("DestinationPort") else ""
        return f"`{_short(image)} -> {event['DestinationIp']}{port}`"
    return next((f"`{_short(event[f])}`" for f in _KEY_FIELDS if event.get(f)), "")


def render_scan_markdown(result: ScanResult) -> str:
    lines = ["# Detection Scan Report", ""]
    lines += [
        f"- **Events scanned:** {result.events_scanned}",
        f"- **Rules evaluated:** {result.rules_loaded}",
        f"- **Alerts:** {len(result.alerts)}",
    ]
    if result.by_level:
        lines.append("- **By severity:** " + ", ".join(f"{k}: {v}" for k, v in result.by_level.items()))
    if result.techniques:
        lines.append("- **ATT&CK techniques observed:** " + ", ".join(result.techniques))
    lines.append("")

    if not result.alerts:
        lines.append("_No detections fired._")
        return "\n".join(lines) + "\n"

    lines += ["## Rules fired", "", "| Rule | Hits |", "|---|---|"]
    lines += [f"| {_short(title)} | {n} |" for _, title, n in result.by_rule]
    lines.append("")

    lines += ["## Host timelines", ""]
    for host, alerts in result.timeline().items():
        lines += [f"### {host}", "", "| Time | Level | Rule | Techniques | Evidence |", "|---|---|---|---|---|"]
        for a in alerts:
            evidence = _evidence(a.event)
            lines.append(
                f"| {a.timestamp or '-'} | {a.level} | {_short(a.rule_title, 60)} | "
                f"{', '.join(a.techniques) or '-'} | {evidence} |"
            )
        lines.append("")
    return "\n".join(lines)


def render_test_text(report: TestReport, total_rules: int) -> str:
    lines = []
    for r in report.results:
        mark = "PASS" if r.passed else "FAIL"
        exp = "match" if r.expected else "no_match"
        line = f"[{mark}] {r.rule_title} :: {r.name} (expect {exp})"
        lines.append(line)
    for orphan in report.orphan_files:
        lines.append(f"[ERROR] orphan test file: {orphan}")
    lines.append("")
    passed = len(report.results) - len(report.failures)
    lines.append(f"{passed}/{len(report.results)} cases passed")
    lines.append(
        f"rule test coverage: {report.coverage(total_rules):.0%} "
        f"({total_rules - len(report.untested_rules)}/{total_rules} rules have tests)"
    )
    for r in report.untested_rules:
        lines.append(f"  untested: {r.title} ({r.source})")
    for r in report.rules_missing_negative:
        lines.append(f"  no negative (no_match) case: {r.title}")
    return "\n".join(lines) + "\n"


def attack_coverage(rules: list[Rule]) -> dict[str, dict[str, list[str]]]:
    """Map tactic -> technique -> [rule titles]."""
    cov: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for rule in rules:
        pairs = rule.tactic_technique_pairs()
        if not pairs:
            pairs = [(t, "(no technique tag)") for t in rule.tactics] or [("unmapped", "(no technique tag)")]
        for tactic, tech in pairs:
            cov[tactic][tech].append(rule.title)
    order = {t: i for i, t in enumerate(_TACTIC_ORDER + ["unmapped"])}
    return {
        t: {k: sorted(v) for k, v in sorted(cov[t].items())}
        for t in sorted(cov, key=lambda t: order.get(t, 99))
    }


def render_coverage_markdown(rules: list[Rule]) -> str:
    cov = attack_coverage(rules)
    covered_tactics = [t for t in cov if t != "unmapped"]
    techniques = {tech for techs in cov.values() for tech in techs if tech.startswith("T")}
    lines = [
        "# ATT&CK Coverage",
        "",
        f"{len(rules)} rules cover {len(techniques)} techniques across "
        f"{len(covered_tactics)}/{len(_TACTIC_ORDER)} tactics.",
        "",
        "| Tactic | Technique | Rules |",
        "|---|---|---|",
    ]
    for tactic, techs in cov.items():
        for tech, titles in techs.items():
            lines.append(f"| {tactic.replace('_', ' ').title()} | {tech} | {'; '.join(titles)} |")
    gaps = [t for t in _TACTIC_ORDER if t not in cov]
    if gaps:
        lines += ["", "**Tactic gaps:** " + ", ".join(t.replace("_", " ") for t in gaps)]
    return "\n".join(lines) + "\n"
