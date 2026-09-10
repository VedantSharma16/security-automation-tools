"""Subprocess wrappers around the sibling security-automation-tools projects.

Each wrapper treats its target project as an external "tool" the agent can
call — exactly the shape a real function-calling/agentic pipeline uses for
tool execution — rather than importing the sibling packages directly. That
keeps this project decoupled from their internals (each has its own
dependencies and CLI contract) and means a broken or missing dependency in
one tool (e.g. `psutil` not being installed) degrades to a reported error
for that tool instead of crashing the whole triage run.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TIMEOUT_SECONDS = 30

# Severity vocabulary shared by all three sibling tools.
SEVERITY_ORDER = ("none", "low", "medium", "high", "critical")


def severity_rank(severity: str | None) -> int:
    severity = (severity or "none").lower()
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0


@dataclass
class ToolResult:
    """Normalized outcome of running one specialist tool."""

    tool: str
    status: str  # "ok" | "error" | "skipped"
    command: list[str] = field(default_factory=list)
    severity: str | None = None
    finding_count: int = 0
    risk_score: int | None = None
    headline: str = ""
    raw: dict | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "status": self.status,
            "command": self.command,
            "severity": self.severity,
            "finding_count": self.finding_count,
            "risk_score": self.risk_score,
            "headline": self.headline,
            "error": self.error,
            "raw": self.raw,
        }


def skipped(tool: str, reason: str) -> ToolResult:
    return ToolResult(tool=tool, status="skipped", headline=reason)


def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[subprocess.CompletedProcess | None, str | None]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        return None, f"could not launch tool: {exc}"
    except subprocess.TimeoutExpired:
        return None, f"tool timed out after {timeout}s"
    return proc, None


def run_log_triage(
    evidence_path: Path, repo_root: Path, timeout: int = DEFAULT_TIMEOUT_SECONDS
) -> ToolResult:
    """Run log-triage-assistant against an auth-log-style evidence file."""
    project_dir = repo_root / "log-triage-assistant"
    cmd = [sys.executable, "-m", "logtriage.cli", "scan", str(evidence_path), "--format", "json"]

    proc, err = _run(cmd, project_dir, timeout)
    if err:
        return ToolResult(tool="log_triage", status="error", command=cmd, error=err)
    if proc.returncode != 0:
        return ToolResult(
            tool="log_triage",
            status="error",
            command=cmd,
            error=proc.stderr.strip() or f"exited with code {proc.returncode}",
        )

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return ToolResult(tool="log_triage", status="error", command=cmd, error=f"invalid JSON output: {exc}")

    summary = data["summary"]
    # logtriage reports its Severity enum names in upper case ("CRITICAL"),
    # unlike ioc_triage/process_hunter's lower-case strings -- normalize here
    # so the aggregator can compare severities across tools uniformly.
    severity = (summary.get("highest_severity") or "none").lower()
    return ToolResult(
        tool="log_triage",
        status="ok",
        command=cmd,
        severity=severity,
        finding_count=summary["total_findings"],
        risk_score=summary["risk_score"],
        headline=(
            f"{summary['total_findings']} auth-log finding(s), "
            f"highest severity {severity}, risk score {summary['risk_score']}/100"
        ),
        raw=data,
    )


def run_ioc_triage(
    evidence_path: Path, repo_root: Path, timeout: int = DEFAULT_TIMEOUT_SECONDS
) -> ToolResult:
    """Run ioc-triage-assistant against alert/report-style evidence text."""
    project_dir = repo_root / "ioc-triage-assistant"
    cmd = [sys.executable, "-m", "ioc_triage.cli", "--file", str(evidence_path), "--json"]

    proc, err = _run(cmd, project_dir, timeout)
    if err:
        return ToolResult(tool="ioc_triage", status="error", command=cmd, error=err)
    if proc.returncode != 0:
        return ToolResult(
            tool="ioc_triage",
            status="error",
            command=cmd,
            error=proc.stderr.strip() or f"exited with code {proc.returncode}",
        )

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return ToolResult(tool="ioc_triage", status="error", command=cmd, error=f"invalid JSON output: {exc}")

    severity = data.get("severity") or "none"
    malicious_hits = [e for e in data["enrichment"] if e["is_known_malicious"]]
    return ToolResult(
        tool="ioc_triage",
        status="ok",
        command=cmd,
        severity=severity,
        finding_count=len(data["indicators"]),
        risk_score=None,
        headline=(
            f"{len(data['indicators'])} indicator(s) extracted, "
            f"{len(malicious_hits)} known-malicious, severity {severity}"
        ),
        raw=data,
    )


def run_process_hunter(
    repo_root: Path, min_severity: str = "low", timeout: int = DEFAULT_TIMEOUT_SECONDS
) -> ToolResult:
    """Run process_threat_hunter's live scan of the current host's processes."""
    project_dir = repo_root / "process_threat_hunter"

    with tempfile.TemporaryDirectory() as tmp:
        json_out = Path(tmp) / "hunter_report.json"
        cmd = [
            sys.executable,
            "-m",
            "hunter.cli",
            "--no-color",
            "--min-severity",
            min_severity,
            "--json-out",
            str(json_out),
        ]

        proc, err = _run(cmd, project_dir, timeout)
        if err:
            return ToolResult(tool="process_hunter", status="error", command=cmd, error=err)

        # Exit code 1 legitimately means "findings present" for this tool, so the
        # only reliable success signal is whether the JSON report was written --
        # a crash before that point (e.g. a missing `psutil` dependency) leaves no
        # file behind regardless of the exit code Python happens to report.
        if not json_out.exists():
            error = proc.stderr.strip() or f"exited with code {proc.returncode} and produced no report"
            return ToolResult(tool="process_hunter", status="error", command=cmd, error=error)

        data = json.loads(json_out.read_text(encoding="utf-8"))

    severity = data.get("highest_severity") or "none"
    return ToolResult(
        tool="process_hunter",
        status="ok",
        command=cmd,
        severity=severity,
        finding_count=data["finding_count"],
        risk_score=None,
        headline=(
            f"{data['finding_count']} suspicious process finding(s) out of "
            f"{data['process_count']} scanned, highest severity {severity}"
        ),
        raw=data,
    )
