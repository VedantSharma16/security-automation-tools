"""The deterministic (offline) ReAct-style agent loop.

The agent doesn't just run every tool against every entity in one shot — it
works through a prioritized queue one action at a time, records a
Thought/Action/Observation trace for each step, and stops itself once it has
enough evidence (or it runs out of steps). This is the same control flow an
LLM-driven tool-calling loop follows; here the "planner" is a deterministic
policy instead of a model, which keeps the orchestration logic itself fully
testable without network access or an API key.
"""

from __future__ import annotations

from ir_agent.entities import extract_entities
from ir_agent.models import AgentStep, IncidentVerdict
from ir_agent.synthesis import synthesize_verdict
from ir_agent.tools import IntelStore, TOOL_FUNCTIONS, default_store

DEFAULT_MAX_STEPS = 8


def _build_action_queue(incident_text: str) -> list[tuple[str, str, str]]:
    """Return an ordered list of (tool, input, thought) actions to take.

    CVEs are checked first (an exploited CVE is the single strongest severity
    signal), then IPs, then domains, then finally a keyword lookup against
    the incident text as a whole once specific entities are exhausted.
    """
    entities = extract_entities(incident_text)
    queue: list[tuple[str, str, str]] = []

    for cve in entities.cves:
        queue.append(("check_cve", cve, f"Incident text references {cve}; checking severity and exploitation status."))
    for ip in entities.ips:
        queue.append(("check_ip_reputation", ip, f"Incident text references IP {ip}; checking local threat-intel reputation."))
    for domain in entities.domains:
        queue.append(("check_domain_reputation", domain, f"Incident text references domain {domain}; checking local threat-intel reputation."))

    queue.append((
        "lookup_attack_technique",
        incident_text,
        "Matching incident language against known ATT&CK technique keywords for context.",
    ))
    return queue


def run_offline(incident_text: str, max_steps: int = DEFAULT_MAX_STEPS, store: IntelStore | None = None) -> IncidentVerdict:
    """Run the deterministic planner's agent loop to completion."""
    store = store or default_store()
    queue = _build_action_queue(incident_text)

    trace: list[AgentStep] = []
    evidence = []

    for step_num, (tool, tool_input, thought) in enumerate(queue[:max_steps], start=1):
        fn = TOOL_FUNCTIONS[tool]
        observation = fn(tool_input, store)
        trace.append(AgentStep(step=step_num, thought=thought, tool=tool, tool_input=tool_input, observation=observation))
        evidence.append(observation)

    if len(queue) > max_steps:
        trace.append(
            AgentStep(
                step=max_steps + 1,
                thought=f"Reached max_steps={max_steps} with {len(queue) - max_steps} action(s) still queued; finishing with partial evidence.",
                tool="finish",
                tool_input="",
                observation=None,
            )
        )
    else:
        trace.append(
            AgentStep(
                step=len(queue) + 1,
                thought="No further entities or lookups pending; synthesizing final verdict.",
                tool="finish",
                tool_input="",
                observation=None,
            )
        )

    return synthesize_verdict(incident_text, evidence, trace, llm_backed=False)


def run_agent(
    incident_text: str,
    max_steps: int = DEFAULT_MAX_STEPS,
    api_key: str | None = None,
    model: str | None = None,
    store: IntelStore | None = None,
) -> IncidentVerdict:
    """Run the incident-response agent, preferring the LLM planner when live.

    Falls back to the deterministic offline planner if no API key/SDK is
    available, or if the LLM planner raises for any reason (network error,
    malformed tool call, rate limit, ...) — the incident always gets a
    verdict, live or offline.
    """
    from ir_agent.llm_agent import LLMAgent  # local import: keep anthropic optional

    store = store or default_store()
    llm = LLMAgent(api_key=api_key, model=model)
    if llm.is_live:
        try:
            return llm.run(incident_text, max_steps=max_steps, store=store)
        except Exception as exc:  # pragma: no cover - network/SDK failure path
            verdict = run_offline(incident_text, max_steps=max_steps, store=store)
            verdict.summary += f"\n\n[LLM planner failed, offline planner used instead: {exc}]"
            return verdict
    return run_offline(incident_text, max_steps=max_steps, store=store)
