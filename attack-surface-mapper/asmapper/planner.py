"""Agentic recon planner.

Live mode runs a genuine Claude *tool-use loop*: the model is handed the
already-fetched target response plus a small toolbox (header audit, robots/
sitemap scan, tech fingerprinting, and — only if explicitly enabled — an
exposure-path probe), and it decides which tools to call, in what order, and
when it has gathered enough to stop and summarize. This is a different LLM
pattern than the RAG retrieval used in ``ioc-triage-assistant`` — here the
model is driving tool selection, not just consuming retrieved context.

Without ``ANTHROPIC_API_KEY`` (or with ``force_offline=True``), a
deterministic offline planner runs the same tools in a fixed, sensible
order, so the CLI is fully usable — and the test suite fully runnable —
without any network access to an LLM provider. Both paths return the same
:class:`ScanState` shape, so reporting doesn't need to know which one ran.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .exposure_checks import check_exposure_paths
from .fetcher import FetchResult, fetch
from .fingerprint import fingerprint
from .headers_audit import audit_headers
from .models import Finding
from .robots import scan as scan_robots

DEFAULT_MODEL = "claude-sonnet-5"
MAX_AGENT_STEPS = 6

AGENT_SYSTEM_PROMPT = (
    "You are an attack-surface reconnaissance planner supporting an AUTHORIZED "
    "security assessment (the operator has explicit permission to test this "
    "target — a pentest engagement, a bug bounty program, or an internal "
    "blue-team exposure review). You have already fetched the target's root "
    "page once; its status, headers, and a body excerpt are in the first "
    "user message. Decide which passive analysis tools to run and in what "
    "order to build a prioritized attack-surface report. Call exactly one "
    "tool per turn, and never call the same tool twice. You do not need to "
    "call every tool — stop as soon as you have enough to report on. Once "
    "you are done calling tools, reply with a short 2-4 sentence assessment: "
    "what the attack surface looks like and the single most important next "
    "step for the operator to manually verify."
)


def _tool_specs(include_exposure: bool) -> list[dict]:
    specs = [
        {
            "name": "run_header_audit",
            "description": (
                "Analyze the HTTP response headers already fetched from the target for "
                "missing security headers, weak cookie flags, and version disclosure."
            ),
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "run_recon_files_scan",
            "description": "Fetch and parse robots.txt and sitemap.xml from the target for disclosed or hidden paths.",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "run_fingerprint",
            "description": (
                "Fingerprint the web server software, framework, and CMS from the "
                "already-fetched headers and page body via signature matching."
            ),
            "input_schema": {"type": "object", "properties": {}},
        },
    ]
    if include_exposure:
        specs.append(
            {
                "name": "run_exposure_check",
                "description": (
                    "Issue a small number of GET requests for a curated list of commonly-exposed "
                    "sensitive paths (.env, .git/config, backups, admin panels) and report which "
                    "respond. This performs live requests beyond the initial fetch; only call it "
                    "because the operator has explicitly enabled it, which they have for this run."
                ),
                "input_schema": {"type": "object", "properties": {}},
            }
        )
    return specs


@dataclass
class PlanStep:
    tool: str
    reason: str


@dataclass
class ScanState:
    base_url: str
    target: FetchResult
    findings: list[Finding] = field(default_factory=list)
    trace: list[PlanStep] = field(default_factory=list)
    agent_assessment: str | None = None
    planner_mode: str = "offline"


class Planner:
    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        allow_exposure_checks: bool = False,
        force_offline: bool = False,
    ):
        self.model = model
        self.allow_exposure_checks = allow_exposure_checks
        self.api_key = None
        self._client = None
        if not force_offline:
            self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if self.api_key:
                try:
                    import anthropic  # type: ignore

                    self._client = anthropic.Anthropic(api_key=self.api_key)
                except ImportError:
                    self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def run(self, base_url: str, fetch_fn=fetch) -> ScanState:
        target = fetch_fn(base_url)
        state = ScanState(base_url=base_url, target=target)
        if not target.ok:
            state.trace.append(
                PlanStep(tool="none", reason=f"initial fetch failed: {target.error or target.status}")
            )
            state.agent_assessment = "Target unreachable; no further checks were run."
            return state

        if self._client is not None:
            state.planner_mode = "agentic"
            self._run_agentic(state, fetch_fn)
        else:
            state.planner_mode = "offline"
            self._run_deterministic(state, fetch_fn)
        return state

    # ---- deterministic fallback: fixed order, every available tool ----
    def _run_deterministic(self, state: ScanState, fetch_fn) -> None:
        state.trace.append(PlanStep(tool="run_header_audit", reason="offline planner: fixed order, headers first"))
        state.findings += audit_headers(state.target.headers)

        state.trace.append(PlanStep(tool="run_recon_files_scan", reason="offline planner: fixed order"))
        state.findings += scan_robots(state.base_url, fetch_fn)

        state.trace.append(PlanStep(tool="run_fingerprint", reason="offline planner: fixed order"))
        state.findings += fingerprint(state.target.headers, state.target.body)

        if self.allow_exposure_checks:
            state.trace.append(
                PlanStep(tool="run_exposure_check", reason="offline planner: exposure checks explicitly enabled")
            )
            state.findings += check_exposure_paths(state.base_url, fetch_fn)

        state.agent_assessment = (
            "[offline deterministic planner — set ANTHROPIC_API_KEY for an agentic run] "
            f"Ran all available passive checks in fixed order; {len(state.findings)} finding(s) reported."
        )

    # ---- agentic: real Claude tool-use loop ----
    def _run_agentic(self, state: ScanState, fetch_fn) -> None:
        tool_specs = _tool_specs(self.allow_exposure_checks)
        allowed_names = {spec["name"] for spec in tool_specs}
        called: set[str] = set()

        target = state.target
        body_snippet = (target.body or "")[:1500]
        messages: list[dict] = [
            {
                "role": "user",
                "content": (
                    f"Target: {state.base_url}\n"
                    f"HTTP status: {target.status}\n"
                    f"Response headers: {json.dumps(target.headers, indent=2)}\n"
                    f"Response body (truncated to 1500 chars):\n{body_snippet}"
                ),
            }
        ]

        for _ in range(MAX_AGENT_STEPS):
            response = self._client.messages.create(
                model=self.model,
                max_tokens=800,
                system=AGENT_SYSTEM_PROMPT,
                tools=tool_specs,
                messages=messages,
            )
            tool_uses = [block for block in response.content if getattr(block, "type", "") == "tool_use"]

            if not tool_uses:
                text = "".join(
                    block.text for block in response.content if getattr(block, "type", "") == "text"
                ).strip()
                state.agent_assessment = text or None
                return

            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for call in tool_uses:
                if call.name not in allowed_names or call.name in called:
                    result_text = f"Skipped: '{call.name}' was already called or is not offered this run."
                else:
                    called.add(call.name)
                    result_text = self._execute_tool(call.name, state, fetch_fn)
                tool_results.append({"type": "tool_result", "tool_use_id": call.id, "content": result_text})
            messages.append({"role": "user", "content": tool_results})

        state.agent_assessment = (
            f"[agentic planner hit the {MAX_AGENT_STEPS}-step cap before producing a final summary] "
            f"{len(state.findings)} finding(s) reported from {len(called)} tool call(s)."
        )

    def _execute_tool(self, name: str, state: ScanState, fetch_fn) -> str:
        if name == "run_header_audit":
            new = audit_headers(state.target.headers)
            reason = "agent chose to audit response headers"
        elif name == "run_recon_files_scan":
            new = scan_robots(state.base_url, fetch_fn)
            reason = "agent chose to check robots.txt/sitemap.xml"
        elif name == "run_fingerprint":
            new = fingerprint(state.target.headers, state.target.body)
            reason = "agent chose to fingerprint the tech stack"
        elif name == "run_exposure_check":
            new = check_exposure_paths(state.base_url, fetch_fn)
            reason = "agent chose to probe common exposure paths (explicitly enabled)"
        else:  # pragma: no cover - guarded by allowed_names in _run_agentic
            return f"Unknown tool: {name}"

        state.trace.append(PlanStep(tool=name, reason=reason))
        state.findings += new
        if not new:
            return "No findings from this check."
        return "\n".join(f"- [{f.severity.name}] {f.title}: {f.detail}" for f in new)
