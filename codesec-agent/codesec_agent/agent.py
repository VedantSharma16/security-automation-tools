"""The agentic review loop.

Unlike a single prompt-and-response LLM call, this drives a genuine
multi-turn tool-use loop: given only a directory, the model decides which
files are worth reading, asks the rule engine to check specific files,
greps for patterns it's suspicious about, and only then writes its review —
calling tools itself rather than being handed pre-computed context.

The list of *findings* in the final report, however, always comes from an
independently-computed full-repository scan (:mod:`.scanner`), not from
whatever the model happened to inspect. This mirrors the retrieval-grounded
pattern used elsewhere in this repo (see ``ioc-triage-assistant``): an LLM is
good at writing a prioritized, readable narrative, and bad at being trusted
as the sole source of "here is the complete list of vulnerabilities" — a file
it never asked to read cannot appear in its findings. Offline (no API key),
the narrative is a deterministic template driven by that same scan, so the
tool is fully usable and testable without any network access.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from . import tools
from .rules import Finding
from .scanner import ScanResult, scan_directory

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TURNS = 8

SYSTEM_PROMPT = (
    "You are an application security engineer performing a source code review. "
    "You have tools to list files, read them, run a static-analysis rule engine "
    "against a specific file, and grep for patterns. Use them to investigate the "
    "codebase yourself rather than guessing — prioritize files that look "
    "security-relevant (auth, database access, subprocess/shell use, "
    "deserialization, file I/O). When you're done investigating, write a short "
    "review: what the most important risks are, why they matter in context, and "
    "what you'd fix first. Be concrete and reference file names and line numbers "
    "you actually observed through the tools."
)


@dataclass
class AgentReport:
    root: str
    files_scanned: list[str]
    findings: list[Finding]
    severity_counts: dict[str, int]
    narrative: str
    llm_backed: bool
    tool_calls: list[dict] = field(default_factory=list)
    parse_errors: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "severity_counts": self.severity_counts,
            "narrative": self.narrative,
            "llm_backed": self.llm_backed,
            "tool_calls": self.tool_calls,
            "parse_errors": self.parse_errors,
        }


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _offline_narrative(scan: ScanResult, counts: dict[str, int]) -> str:
    if not scan.findings:
        return (
            "[offline heuristic summary — set ANTHROPIC_API_KEY for an LLM-driven review] "
            f"No findings across {len(scan.files_scanned)} file(s) scanned."
        )

    top = scan.findings[:5]
    lines = [
        "[offline heuristic summary — set ANTHROPIC_API_KEY for an LLM-driven agentic review]",
        f"Scanned {len(scan.files_scanned)} file(s): "
        f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
        f"{counts['low']} low severity finding(s).",
        "Highest-priority findings:",
    ]
    for f in top:
        lines.append(f"  - [{f.severity.upper()}] {f.file}:{f.line} {f.title} ({f.cwe}) — {f.remediation}")
    if len(scan.findings) > len(top):
        lines.append(f"  ... and {len(scan.findings) - len(top)} more finding(s); see the full report.")
    return "\n".join(lines)


class CodeSecurityAgent:
    """Runs a directory review, live via Claude tool-use when a key is available."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_turns: int = DEFAULT_MAX_TURNS,
        client: object | None = None,
    ):
        self.model = model
        self.max_turns = max_turns
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = client
        if self._client is None and self.api_key:
            try:
                import anthropic  # type: ignore

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def review(self, root: str) -> AgentReport:
        scan = scan_directory(root)
        counts = _severity_counts(scan.findings)

        if self._client is None:
            narrative = _offline_narrative(scan, counts)
            tool_calls: list[dict] = []
        else:
            try:
                narrative, tool_calls = self._run_agent_loop(root)
            except Exception as exc:  # pragma: no cover - network/SDK failure path
                narrative = _offline_narrative(scan, counts) + f"\n\n[LLM agent loop failed, offline fallback used: {exc}]"
                tool_calls = []

        return AgentReport(
            root=str(root),
            files_scanned=scan.files_scanned,
            findings=scan.findings,
            severity_counts=counts,
            narrative=narrative,
            llm_backed=self._client is not None,
            tool_calls=tool_calls,
            parse_errors=scan.parse_errors,
        )

    def _run_agent_loop(self, root: str) -> tuple[str, list[dict]]:
        messages: list[dict] = [
            {
                "role": "user",
                "content": f"Review the Python code under the project root for security issues. "
                f"Start by listing the files present.",
            }
        ]
        tool_calls: list[dict] = []

        for _ in range(self.max_turns):
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                tools=tools.TOOL_SCHEMAS,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason != "tool_use":
                return _extract_text(response.content), tool_calls

            tool_results = []
            for block in response.content:
                if getattr(block, "type", None) != "tool_use":
                    continue
                result = tools.execute_tool(block.name, block.input, root)
                tool_calls.append({"name": block.name, "input": block.input})
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(result)}
                )
            messages.append({"role": "user", "content": tool_results})

        # Ran out of turns without the model wrapping up on its own: ask it to
        # summarize with whatever it's gathered so far, no more tool calls offered.
        response = self._client.messages.create(
            model=self.model,
            max_tokens=1500,
            system=SYSTEM_PROMPT
            + " You have used all available tool calls; write your review now based on what you've seen.",
            messages=messages,
        )
        return _extract_text(response.content), tool_calls


def _extract_text(content_blocks) -> str:
    parts = [block.text for block in content_blocks if getattr(block, "type", "") == "text"]
    return "".join(parts).strip()
