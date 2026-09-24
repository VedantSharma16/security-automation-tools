"""Running every registered rule against a resource set."""

from __future__ import annotations

from .models import SEVERITY_RANK
from .rules import ALL_CHECKS


def scan(resources: list) -> list:
    """Run all checks against `resources` and return findings, highest
    severity first, then by resource address, then by rule id."""
    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(resources))

    return sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK[f.severity], f.resource_address, f.rule_id),
    )
