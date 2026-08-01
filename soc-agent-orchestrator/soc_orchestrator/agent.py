"""The agentic investigation loop.

Given a case (evidence files plus an optional incident description), an LLM
plans which specialist tools to call, in what order, reads their structured
output, and decides whether it has enough information to conclude. This is a
genuine tool-use loop against the Claude Messages API -- the model chooses
which of the three specialist tools apply to a given case and can skip ones
that don't -- not a hardcoded call sequence.

A DeterministicPlanner provides a fully offline fallback (no API key, no
`anthropic` package installed): it runs every specialist tool that
plausibly applies to the case's evidence, in a fixed order. This mirrors the
offline-first design of the other tools in this repo -- the orchestrator
still produces a complete report with no network access or API key
required, and it's what the test suite and CI run against.

Regardless of which planner ran, the final severity, risk score, and
recommended actions are always computed deterministically from the raw tool
outputs in `synthesis.py` -- the LLM (when used) only gets to choose *which*
tools to call and write the prose narrative, never the verdict itself.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Protocol

from .case import CaseManifest, load_case
from .synthesis import InvestigationReport, synthesize
from .tools import DISPATCH, TOOL_SPECS, ToolResult

DEFAULT_MODEL = "claude-sonnet-5"
MAX_AGENT_TURNS = 6

SYSTEM_PROMPT = (
    "You are a SOC investigation agent. You are given a manifest of evidence files "
    "for a security case and access to three specialist tools. Decide which tools "
    "apply: do not call a tool on a file whose declared kind doesn't match what that "
    "tool expects, and only call run_process_hunt if checking the live host is "
    "relevant to this case. Call as many tools as are relevant, in any order, then "
    "stop calling tools once you have enough information. Your final response (once "
    "you stop calling tools) should be a short analyst narrative: what happened, how "
    "confident you are, and what the analyst should do next. Ground every claim in "
    "the tool outputs you received -- never invent IPs, users, hashes, or events that "
    "weren't in a tool result."
)


class Planner(Protocol):
    def run(self, case: CaseManifest) -> tuple[list[ToolResult], str | None]: ...


class DeterministicPlanner:
    """Offline fallback: calls every specialist tool that applies to the case's evidence."""

    def run(self, case: CaseManifest) -> tuple[list[ToolResult], str | None]:
        results: list[ToolResult] = []
        for f in case.files_of_kind("log"):
            results.append(DISPATCH["run_log_triage"](logfile=str(f.path)))
        for f in case.files_of_kind("alert"):
            results.append(DISPATCH["run_ioc_triage"](alert_file=str(f.path)))
        results.append(DISPATCH["run_process_hunt"]())
        return results, None


class LLMPlanner:
    """Real tool-use loop against the Claude Messages API."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None, client=None):
        if client is not None:
            self._client = client
        else:
            from anthropic import Anthropic  # optional dependency, imported lazily

            self._client = Anthropic(api_key=api_key) if api_key else Anthropic()
        self._model = model

    def run(self, case: CaseManifest) -> tuple[list[ToolResult], str | None]:
        tool_results: list[ToolResult] = []
        messages = [
            {
                "role": "user",
                "content": (
                    "Case manifest:\n"
                    + json.dumps(case.to_dict(), indent=2)
                    + "\n\nInvestigate this case."
                ),
            }
        ]

        for _ in range(MAX_AGENT_TURNS):
            response = self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=TOOL_SPECS,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": response.content})

            tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
            if not tool_use_blocks:
                narrative = "".join(b.text for b in response.content if b.type == "text")
                return tool_results, narrative

            tool_result_blocks = []
            for block in tool_use_blocks:
                handler = DISPATCH.get(block.name)
                result = (
                    handler(**block.input)
                    if handler is not None
                    else ToolResult(tool=block.name, ok=False, error="unknown tool")
                )
                tool_results.append(result)
                tool_result_blocks.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result.to_dict()),
                    }
                )
            messages.append({"role": "user", "content": tool_result_blocks})

        # Ran out of turns without the model concluding; fall back to the
        # deterministic narrative built from whatever tool results we have.
        return tool_results, None


def _select_planner(use_llm: bool | None, model: str) -> tuple[Planner, bool]:
    if use_llm is None:
        use_llm = bool(os.environ.get("ANTHROPIC_API_KEY"))

    if not use_llm:
        return DeterministicPlanner(), False

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "note: --llm requested but ANTHROPIC_API_KEY is not set; "
            "falling back to the deterministic offline planner.",
            file=sys.stderr,
        )
        return DeterministicPlanner(), False

    try:
        return LLMPlanner(model=model, api_key=api_key), True
    except ImportError:
        print(
            "note: --llm requested but the 'anthropic' package is not installed; "
            "falling back to the deterministic offline planner.",
            file=sys.stderr,
        )
        return DeterministicPlanner(), False


def investigate(
    case_dir: str,
    incident_description: str = "",
    use_llm: bool | None = None,
    model: str = DEFAULT_MODEL,
) -> InvestigationReport:
    """Run a full investigation over a case directory and return the merged report."""
    case = load_case(case_dir, incident_description=incident_description)
    planner, llm_backed = _select_planner(use_llm, model)
    tool_results, narrative = planner.run(case)
    return synthesize(
        case=case,
        tool_results=tool_results,
        narrative=narrative,
        llm_backed=llm_backed,
        generated_at=datetime.now().isoformat(),
    )
