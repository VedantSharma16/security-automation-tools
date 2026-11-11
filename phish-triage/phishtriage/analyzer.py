"""High-level entry points: raw email in, triage report dict out."""

from __future__ import annotations

from pathlib import Path

from .checks import run_checks
from .parser import parse_bytes
from .report import build_report
from .scoring import score


def analyze_bytes(raw: bytes, source: str = "<bytes>") -> dict:
    email = parse_bytes(raw)
    findings = run_checks(email)
    return build_report(source, email, findings, score(findings))


def analyze_file(path: str | Path) -> dict:
    path = Path(path)
    return analyze_bytes(path.read_bytes(), source=str(path))
