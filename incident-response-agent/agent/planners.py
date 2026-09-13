"""Planners: the "brain" that decides the agent's next move each turn.

:class:`OfflinePlanner` is a deterministic, dependency-free stand-in for an
LLM. It follows a fixed investigative playbook (pull logs -> triage external
IPs -> check running processes -> pivot on suspicious ones -> conclude), so
the whole agent loop is testable without any API access. :class:`ClaudePlanner`
drives the same loop with real tool-use calls to the Claude API when
``ANTHROPIC_API_KEY`` is available.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass

from .engine import FinalStep, Planner, ToolCallStep, Turn
from .tools import TOOL_SCHEMAS

DEFAULT_MODEL = "claude-sonnet-5"

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SYSTEM_PROMPT = (
    "You are an incident-response agent investigating a security alert. You "
    "have a fixed set of read-only tools to query logs, threat intel, and "
    "running processes. Call one tool at a time and reason about the result "
    "before deciding on the next step. Do not guess at facts you have not "
    "observed through a tool call. Once you have enough evidence, stop "
    "calling tools and reply with ONLY a JSON object of the form "
    '{"verdict": "malicious"|"benign"|"inconclusive", '
    '"severity": "critical"|"high"|"medium"|"low"|"informational", '
    '"summary": "<2-4 sentence analyst summary with concrete next steps>"}.'
)


def _tool_calls(transcript: list[Turn]) -> list[Turn]:
    return [t for t in transcript if t.action == "tool_call"]


_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_internal(ip: str) -> bool:
    """True for our own lab address space (RFC 1918 + loopback/link-local).

    Deliberately narrower than :attr:`ipaddress.IPv4Address.is_private`,
    which also lumps in the RFC 5737 documentation ranges (used here to
    stand in for "the internet") as private.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr in network for network in _INTERNAL_NETWORKS)


def _extract_external_ips(lines: list[str]) -> list[str]:
    seen: list[str] = []
    for line in lines:
        for ip in _IP_RE.findall(line):
            if not _is_internal(ip) and ip not in seen:
                seen.append(ip)
    return seen


class OfflinePlanner:
    """Deterministic playbook: no network access, fully reproducible."""

    def next_step(self, alert: dict, transcript: list[Turn]) -> ToolCallStep | FinalStep:
        host = alert["host"]
        calls = _tool_calls(transcript)
        called_names = [t.name for t in calls]

        if "search_logs" not in called_names:
            return ToolCallStep(
                name="search_logs",
                arguments={"host": host},
                reasoning=f"Establish a timeline for {host} before forming a hypothesis.",
            )

        log_lines: list[str] = []
        for t in calls:
            if t.name == "search_logs" and t.observation:
                log_lines += t.observation["matched_lines"]

        looked_up = {
            t.arguments["indicator"] for t in calls if t.name == "lookup_ioc"
        }
        malicious_hits = {
            t.arguments["indicator"]
            for t in calls
            if t.name == "lookup_ioc" and t.observation and t.observation["is_known_malicious"]
        }

        external_ips = _extract_external_ips(log_lines)
        next_ip = next((ip for ip in external_ips if ip not in looked_up), None)
        if next_ip:
            return ToolCallStep(
                name="lookup_ioc",
                arguments={"indicator": next_ip},
                reasoning=f"External IP {next_ip} appears in {host}'s logs; check it against threat intel.",
            )

        if "get_process_list" not in called_names:
            return ToolCallStep(
                name="get_process_list",
                arguments={"host": host},
                reasoning=f"Check for suspicious processes currently running on {host}.",
            )

        processes = []
        for t in calls:
            if t.name == "get_process_list" and t.observation:
                processes = t.observation["processes"]

        def looks_suspicious(proc: dict) -> bool:
            cmdline = (proc.get("cmdline") or "").lower()
            if any(ip in cmdline for ip in malicious_hits):
                return True
            return "/tmp/." in cmdline or "hidden" in cmdline

        suspicious = next((p for p in processes if looks_suspicious(p)), None)

        if suspicious:
            detail_checked = any(
                t.name == "get_process_detail" and t.arguments.get("pid") == suspicious["pid"]
                for t in calls
            )
            if not detail_checked:
                return ToolCallStep(
                    name="get_process_detail",
                    arguments={"host": host, "pid": suspicious["pid"]},
                    reasoning=(
                        f"Process '{suspicious['name']}' (pid {suspicious['pid']}) has an "
                        "anomalous command line; inspect it directly."
                    ),
                )
            sha256 = suspicious.get("sha256")
            if sha256 and sha256 not in looked_up:
                return ToolCallStep(
                    name="lookup_ioc",
                    arguments={"indicator": sha256},
                    reasoning="Check the suspicious process's file hash against threat intel.",
                )

        return self._final_verdict(host, malicious_hits, suspicious)

    @staticmethod
    def _final_verdict(host: str, malicious_hits: set[str], suspicious: dict | None) -> FinalStep:
        if malicious_hits:
            severity = "critical" if len(malicious_hits) > 1 else "high"
            hits = ", ".join(sorted(malicious_hits))
            proc_note = (
                f" The anomalous process '{suspicious['name']}' (pid {suspicious['pid']}) "
                f"corroborates this."
                if suspicious
                else ""
            )
            return FinalStep(
                verdict="malicious",
                severity=severity,
                summary=(
                    f"Confirmed malicious activity on {host}: indicator(s) {hits} matched the "
                    f"threat-intel feed.{proc_note} Recommend isolating {host} from the network, "
                    "rotating credentials used in the affected session, and preserving the host "
                    "for forensic imaging before remediation."
                ),
            )
        if suspicious:
            return FinalStep(
                verdict="inconclusive",
                severity="medium",
                summary=(
                    f"Process '{suspicious['name']}' (pid {suspicious['pid']}) on {host} has an "
                    "anomalous command line but no indicator matched the local threat-intel feed. "
                    "Recommend manual analyst review and submission of the binary hash to an "
                    "external sandbox before ruling this out."
                ),
            )
        return FinalStep(
            verdict="benign",
            severity="informational",
            summary=(
                f"No indicators of compromise found for {host}: logs show no external IPs of "
                "interest and no suspicious processes were running. No further action needed "
                "beyond routine monitoring."
            ),
        )


@dataclass
class ClaudePlanner:
    """Drives the same loop using the real Claude API tool-use protocol."""

    api_key: str | None = None
    model: str = DEFAULT_MODEL

    def __post_init__(self) -> None:
        self.api_key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None
        if self.api_key:
            try:
                import anthropic  # type: ignore

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None

    @property
    def is_live(self) -> bool:
        return self._client is not None

    def next_step(self, alert: dict, transcript: list[Turn]) -> ToolCallStep | FinalStep:
        if self._client is None:
            raise RuntimeError(
                "ClaudePlanner has no live API client; set ANTHROPIC_API_KEY or use OfflinePlanner."
            )

        messages = [{"role": "user", "content": self._render_prompt(alert, transcript)}]
        response = self._client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=messages,
        )

        for block in response.content:
            if getattr(block, "type", "") == "tool_use":
                return ToolCallStep(name=block.name, arguments=dict(block.input), reasoning="")

        text = "".join(
            block.text for block in response.content if getattr(block, "type", "") == "text"
        ).strip()
        return self._parse_final(text)

    @staticmethod
    def _render_prompt(alert: dict, transcript: list[Turn]) -> str:
        lines = ["## Alert", json.dumps(alert, indent=2), ""]
        if not transcript:
            lines.append("No tools have been called yet. Decide on the first tool to call.")
        else:
            lines.append("## Investigation so far")
            for t in transcript:
                lines.append(f"- Step {t.step_number}: called `{t.name}`({t.arguments})")
                lines.append(f"  Observation: {json.dumps(t.observation)}")
        return "\n".join(lines)

    @staticmethod
    def _parse_final(text: str) -> FinalStep:
        try:
            data = json.loads(text)
            return FinalStep(
                verdict=data["verdict"], severity=data["severity"], summary=data["summary"]
            )
        except (json.JSONDecodeError, KeyError):
            return FinalStep(verdict="inconclusive", severity="unknown", summary=text or "(empty response)")


def get_planner(use_llm: bool, model: str = DEFAULT_MODEL) -> Planner:
    """Return a live Claude planner if requested and available, else the offline one."""
    if use_llm:
        planner = ClaudePlanner(model=model)
        if planner.is_live:
            return planner
    return OfflinePlanner()
