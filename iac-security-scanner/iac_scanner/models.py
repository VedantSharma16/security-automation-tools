"""Core data types shared across the parser, rules, scanner, and report."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


class IacScannerError(Exception):
    """Raised when a plan file can't be parsed into resources."""


@dataclass(frozen=True)
class Resource:
    """A single planned Terraform resource, flattened from `terraform show -json`."""

    address: str
    type: str
    name: str
    mode: str
    provider_name: str
    attributes: dict = field(default_factory=dict)

    def get(self, key: str, default=None):
        return self.attributes.get(key, default)


@dataclass(frozen=True)
class Finding:
    """A single rule violation attached to one resource."""

    rule_id: str
    severity: str
    resource_address: str
    resource_type: str
    title: str
    description: str
    remediation: str
    references: tuple = ()

    def __post_init__(self):
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"invalid severity {self.severity!r}; expected one of {SEVERITIES}")
