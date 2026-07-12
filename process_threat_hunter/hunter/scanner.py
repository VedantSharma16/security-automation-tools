"""Process enumeration and rule evaluation."""

from __future__ import annotations

import time
from dataclasses import dataclass

import psutil

from .rules import Rule


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    exe: str
    cmdline: list
    username: str
    create_time: float

    def fingerprint(self) -> str:
        """A pid-independent identity used for baseline diffing."""
        return f"{self.name}:{self.exe}"


@dataclass(frozen=True)
class Finding:
    process: ProcessInfo
    rule: Rule
    matched_field: str
    matched_text: str


def enumerate_processes() -> list:
    """Snapshot all currently running processes.

    Uses psutil for cross-platform support (Windows/Linux/macOS) instead of
    shelling out to `tasklist`/`ps`, which avoids fragile output parsing and
    works identically across operating systems.
    """
    processes = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "create_time"]):
        try:
            info = proc.info
            processes.append(
                ProcessInfo(
                    pid=info["pid"],
                    name=info.get("name") or "",
                    exe=info.get("exe") or "",
                    cmdline=info.get("cmdline") or [],
                    username=info.get("username") or "",
                    create_time=info.get("create_time") or 0.0,
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Processes can exit mid-enumeration, or be owned by another user;
            # skip rather than aborting the whole scan.
            continue
    return processes


def evaluate(processes: list, rules: list) -> list:
    """Match every process against every rule, returning all findings."""
    findings = []
    for process in processes:
        for rule in rules:
            match = rule.matches(process)
            if match is not None:
                matched_field, matched_text = match
                findings.append(Finding(process, rule, matched_field, matched_text))
    return findings


def scan(rules: list) -> tuple:
    """Run a single scan pass. Returns (processes, findings, scanned_at)."""
    scanned_at = time.time()
    processes = enumerate_processes()
    findings = evaluate(processes, rules)
    return processes, findings, scanned_at
