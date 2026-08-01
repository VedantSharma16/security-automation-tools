"""Wraps this repo's three specialist security tools as agent-callable tools.

Each specialist project (log-triage-assistant, ioc-triage-assistant,
process_threat_hunter) is a standalone, independently-installable package
with its own dependencies and its own test suite. Rather than reaching
across package boundaries with import path hacks, each one is invoked the
same way a human analyst would run it from a terminal: as a subprocess CLI
call from its own project directory, producing structured JSON that this
orchestrator parses. That keeps the three projects fully decoupled from the
orchestrator and from each other.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LOG_TRIAGE_DIR = REPO_ROOT / "log-triage-assistant"
IOC_TRIAGE_DIR = REPO_ROOT / "ioc-triage-assistant"
PROCESS_HUNTER_DIR = REPO_ROOT / "process_threat_hunter"

SUBPROCESS_TIMEOUT_SECONDS = 60


@dataclass
class ToolResult:
    tool: str
    ok: bool
    severity: str | None = None
    summary: str = ""
    data: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "ok": self.ok,
            "severity": self.severity,
            "summary": self.summary,
            "data": self.data,
            "error": self.error,
        }


def _run_subprocess(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    """Invoke a specialist tool's CLI in its own project directory."""
    return subprocess.run(
        [sys.executable, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT_SECONDS,
    )


def run_log_triage(logfile: str) -> ToolResult:
    """Run log-triage-assistant against an auth-log style evidence file."""
    path = Path(logfile).resolve()
    if not path.is_file():
        return ToolResult(tool="run_log_triage", ok=False, error=f"no such file: {logfile}")

    proc = _run_subprocess(
        ["-m", "logtriage.cli", "scan", str(path), "--format", "json"], cwd=LOG_TRIAGE_DIR
    )
    if proc.returncode != 0:
        return ToolResult(
            tool="run_log_triage", ok=False, error=proc.stderr.strip() or "logtriage exited non-zero"
        )

    report = json.loads(proc.stdout)
    summary = report["summary"]
    return ToolResult(
        tool="run_log_triage",
        ok=True,
        severity=summary["highest_severity"],
        summary=(
            f"{summary['total_findings']} auth-log finding(s), "
            f"highest severity {summary['highest_severity']}, risk {summary['risk_score']}/100."
        ),
        data=report,
    )


def run_ioc_triage(alert_file: str) -> ToolResult:
    """Run ioc-triage-assistant against a raw alert/report text file."""
    path = Path(alert_file).resolve()
    if not path.is_file():
        return ToolResult(tool="run_ioc_triage", ok=False, error=f"no such file: {alert_file}")

    proc = _run_subprocess(
        ["-m", "ioc_triage.cli", "--file", str(path), "--json"], cwd=IOC_TRIAGE_DIR
    )
    if proc.returncode != 0:
        return ToolResult(
            tool="run_ioc_triage", ok=False, error=proc.stderr.strip() or "ioc-triage exited non-zero"
        )

    report = json.loads(proc.stdout)
    known_malicious = [e for e in report["enrichment"] if e["is_known_malicious"]]
    return ToolResult(
        tool="run_ioc_triage",
        ok=True,
        severity=report["severity"],
        summary=(
            f"{len(report['indicators'])} indicator(s) extracted, "
            f"{len(known_malicious)} matched known-malicious threat intel, "
            f"severity {report['severity']}."
        ),
        data=report,
    )


def run_process_hunt(min_severity: str = "low") -> ToolResult:
    """Scan the CURRENT LIVE host's running processes for known offensive tooling / LOLBins."""
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "process_report.json"
        proc = _run_subprocess(
            [
                "-m",
                "hunter.cli",
                "--min-severity",
                min_severity,
                "--no-color",
                "--json-out",
                str(out_path),
            ],
            cwd=PROCESS_HUNTER_DIR,
        )
        # process-threat-hunter exits 1 (not 0) when it has findings -- that's a
        # deliberate CI-friendly exit code (see its cli.py), not a failure.
        if proc.returncode not in (0, 1):
            return ToolResult(
                tool="run_process_hunt",
                ok=False,
                error=proc.stderr.strip() or "process-threat-hunter exited abnormally",
            )
        report = json.loads(out_path.read_text(encoding="utf-8"))

    return ToolResult(
        tool="run_process_hunt",
        ok=True,
        severity=report["highest_severity"],
        summary=(
            f"{report['finding_count']} suspicious process finding(s) out of "
            f"{report['process_count']} scanned, highest severity "
            f"{report['highest_severity'] or 'none'}."
        ),
        data=report,
    )


DISPATCH = {
    "run_log_triage": run_log_triage,
    "run_ioc_triage": run_ioc_triage,
    "run_process_hunt": run_process_hunt,
}

TOOL_SPECS = [
    {
        "name": "run_log_triage",
        "description": (
            "Analyze an auth-log style evidence file (SSH/sudo/useradd/crontab log lines) "
            "for brute force, credential compromise, privilege escalation, and persistence "
            "patterns. Only call this on a file already listed as kind='log' in the case "
            "manifest."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "logfile": {"type": "string", "description": "Path to the log evidence file."}
            },
            "required": ["logfile"],
        },
    },
    {
        "name": "run_ioc_triage",
        "description": (
            "Extract indicators of compromise (IPs, domains, hashes, URLs) from a raw alert "
            "or report text file, enrich them against threat intel, and map them to MITRE "
            "ATT&CK techniques. Only call this on a file already listed as kind='alert' in "
            "the case manifest."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_file": {
                    "type": "string",
                    "description": "Path to the alert/report evidence file.",
                }
            },
            "required": ["alert_file"],
        },
    },
    {
        "name": "run_process_hunt",
        "description": (
            "Scan the processes CURRENTLY RUNNING on this host (not a case file) for known "
            "offensive-security tooling and living-off-the-land binaries. Useful to check "
            "whether an intrusion described in the case evidence is still active on this "
            "machine."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "min_severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Minimum severity to report. Defaults to 'low'.",
                }
            },
        },
    },
]
