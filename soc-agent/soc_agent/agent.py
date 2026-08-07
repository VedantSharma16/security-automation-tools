"""The agent loop: orchestrates tool calls into an investigation trace and
a final verdict.

Two interchangeable "brains" produce the same ``InvestigationResult`` shape:

- **Live**: ``llm_client.run_live_agent`` — a real Claude tool-calling
  (ReAct) loop. The model decides what to investigate next.
- **Offline**: ``_run_offline_agent`` below — a fixed but still multi-step,
  multi-tool investigation plan. It calls the exact same tool functions in
  ``tools.py`` and produces the same trace/verdict structure, so the CLI,
  report rendering, and test suite don't need to know which brain ran.
  This keeps the tool fully usable and testable without an API key.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import llm_client, tools
from .extractor import extract_seed_indicators

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass
class AgentStep:
    step: int
    thought: str
    action: str
    action_input: dict
    observation: dict


@dataclass
class InvestigationResult:
    alert_text: str
    steps: list = field(default_factory=list)
    verdict: str = "inconclusive"
    severity: str = "low"
    confidence: str = "low"
    summary: str = ""
    recommended_actions: list = field(default_factory=list)
    llm_backed: bool = False


def investigate(
    alert_text: str,
    api_key: str | None = None,
    model: str = llm_client.DEFAULT_MODEL,
    max_steps: int = llm_client.DEFAULT_MAX_STEPS,
) -> InvestigationResult:
    """Investigate a raw alert and return a complete trace + verdict.

    Uses the live Claude tool-calling agent when ``api_key`` (or
    ``ANTHROPIC_API_KEY``) is set and the ``anthropic`` package is
    installed; otherwise runs the deterministic offline agent.
    """
    resolved_key = llm_client.resolve_api_key(api_key)

    if llm_client.is_available(resolved_key):
        raw_steps, verdict = llm_client.run_live_agent(alert_text, resolved_key, model=model, max_steps=max_steps)
        steps = [AgentStep(**s) for s in raw_steps]
        if verdict is not None:
            return InvestigationResult(alert_text=alert_text, steps=steps, llm_backed=True, **verdict)
        # Live agent exhausted its step budget without a parsed final
        # answer — fall back to the offline synthesis over whatever
        # evidence it did gather, rather than failing the investigation.
        return _synthesize_from_steps(alert_text, steps, llm_backed=True, note="step budget exhausted")

    return _run_offline_agent(alert_text)


def _run_offline_agent(alert_text: str) -> InvestigationResult:
    seed = extract_seed_indicators(alert_text)
    steps: list[AgentStep] = []
    step_num = 0

    def record(thought, action, action_input, observation):
        nonlocal step_num
        step_num += 1
        steps.append(AgentStep(step=step_num, thought=thought, action=action, action_input=action_input, observation=observation))
        return observation

    if not (seed["ips"] or seed["domains"] or seed["processes"]):
        record(
            "No IPs, domains, or recognizable process names were found in the alert text.",
            "extract_seed_indicators",
            {},
            seed,
        )
        return InvestigationResult(
            alert_text=alert_text,
            steps=steps,
            verdict="inconclusive",
            severity="low",
            confidence="low",
            summary="No investigable network or process indicators were found in the alert text.",
            recommended_actions=["Manually review the raw alert/log source for indicators this extractor may have missed."],
            llm_backed=False,
        )

    record(
        f"Scanned the alert text and extracted {len(seed['ips'])} IP(s), "
        f"{len(seed['domains'])} domain(s), and {len(seed['processes'])} process name(s) to investigate.",
        "extract_seed_indicators",
        {},
        seed,
    )

    findings = {"malicious": [], "suspicious": [], "benign": [], "known_bad_process": [], "young_domains": []}

    for ip in seed["ips"]:
        rep = record(
            f"Checking threat-intel reputation for IP {ip}.",
            "lookup_ip_reputation",
            {"ip": ip},
            tools.lookup_ip_reputation(ip),
        )
        findings[rep["verdict"] if rep["verdict"] in findings else "benign"].append(("ip", ip, rep))
        if rep["verdict"] in ("malicious", "suspicious"):
            record(
                f"{ip} was flagged as {rep['verdict']}; pulling GeoIP/hosting context.",
                "geoip_lookup",
                {"ip": ip},
                tools.geoip_lookup(ip),
            )

    for domain in seed["domains"]:
        rep = record(
            f"Checking threat-intel reputation for domain {domain}.",
            "lookup_domain_reputation",
            {"domain": domain},
            tools.lookup_domain_reputation(domain),
        )
        findings[rep["verdict"] if rep["verdict"] in findings else "benign"].append(("domain", domain, rep))
        whois = record(
            f"Looking up WHOIS registration age for {domain} — newly registered domains are a strong signal.",
            "whois_lookup",
            {"domain": domain},
            tools.whois_lookup(domain),
        )
        if whois.get("age_days") is not None and whois["age_days"] < 30:
            findings["young_domains"].append((domain, whois["age_days"]))

    for proc in seed["processes"]:
        baseline = record(
            f"Checking process {proc} against the known-good/known-bad baseline.",
            "check_process_baseline",
            {"process_name": proc},
            tools.check_process_baseline(proc),
        )
        if baseline["status"] == "known_bad":
            findings["known_bad_process"].append((proc, baseline["notes"]))

    query = " ".join(seed["processes"]) or alert_text[:200]
    matched_techniques = record(
        "Searching the ATT&CK reference for techniques matching the observed behavior.",
        "search_attack_techniques",
        {"query": query},
        tools.search_attack_techniques(query),
    )

    return _synthesize(alert_text, steps, findings, matched_techniques)


def _synthesize(alert_text: str, steps: list, findings: dict, matched_techniques: list) -> InvestigationResult:
    malicious = findings["malicious"]
    suspicious = findings["suspicious"]
    known_bad_procs = findings["known_bad_process"]
    young_domains = findings["young_domains"]

    if malicious and known_bad_procs:
        verdict, severity, confidence = "malicious", "critical", "high"
    elif malicious:
        verdict, severity, confidence = "malicious", "high", "high"
    elif known_bad_procs:
        verdict, severity, confidence = "suspicious", "high", "medium"
    elif suspicious or young_domains:
        verdict, severity, confidence = "suspicious", "medium", "medium"
    else:
        verdict, severity, confidence = "benign", "low", "medium"

    summary_parts = []
    if malicious:
        names = ", ".join(f"{kind} {value}" for kind, value, _ in malicious)
        summary_parts.append(f"Confirmed malicious indicators observed: {names}.")
    if known_bad_procs:
        names = ", ".join(name for name, _ in known_bad_procs)
        summary_parts.append(f"Known-bad tooling observed on the host: {names}.")
    if young_domains:
        names = ", ".join(f"{d} ({age}d old)" for d, age in young_domains)
        summary_parts.append(f"Recently registered domain(s) involved: {names}.")
    if matched_techniques:
        top = matched_techniques[0]
        summary_parts.append(f"Behavior most closely resembles ATT&CK {top['id']} ({top['name']}, {top['tactic']}).")
    if not summary_parts:
        summary_parts.append("No indicators matched local threat intel, baseline, or WHOIS age heuristics.")

    actions = []
    if severity in ("critical", "high"):
        actions.append("Isolate the affected host(s) from the network pending further investigation.")
        actions.append("Pivot on the flagged indicators across EDR/SIEM to scope related activity.")
    if known_bad_procs:
        actions.append("Capture a memory/process dump before killing the flagged process for forensic review.")
    if young_domains:
        actions.append("Block the newly registered domain(s) at the DNS/proxy layer pending WHOIS/registrar review.")
    if not actions:
        actions.append("No immediate action required; monitor for recurrence and close if no further activity is observed.")

    return InvestigationResult(
        alert_text=alert_text,
        steps=steps,
        verdict=verdict,
        severity=severity,
        confidence=confidence,
        summary=" ".join(summary_parts),
        recommended_actions=actions,
        llm_backed=False,
    )


def _synthesize_from_steps(alert_text: str, steps: list, llm_backed: bool, note: str) -> InvestigationResult:
    """Best-effort verdict when the live agent ran out of steps: scan the
    observations it already gathered for any known-malicious hits."""
    malicious_hits = [
        s for s in steps
        if isinstance(s.observation, dict) and s.observation.get("verdict") == "malicious"
    ]
    severity = "high" if malicious_hits else "medium"
    confidence = "medium" if malicious_hits else "low"
    verdict = "suspicious" if not malicious_hits else "malicious"
    summary = (
        f"Live agent did not reach a final answer within its step budget ({note}); "
        f"synthesized from {len(steps)} tool call(s) gathered so far."
    )
    return InvestigationResult(
        alert_text=alert_text,
        steps=steps,
        verdict=verdict,
        severity=severity,
        confidence=confidence,
        summary=summary,
        recommended_actions=["Escalate to a human analyst — the automated agent did not converge on a verdict."],
        llm_backed=llm_backed,
    )
