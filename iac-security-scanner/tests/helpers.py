"""Shared test helpers."""

from __future__ import annotations

from iac_scanner.models import Resource

_COUNTER = {"n": 0}


def make_resource(rtype: str, attributes: dict, name: str | None = None, mode: str = "managed") -> Resource:
    _COUNTER["n"] += 1
    name = name or f"r{_COUNTER['n']}"
    return Resource(
        address=f"{rtype}.{name}",
        type=rtype,
        name=name,
        mode=mode,
        provider_name="registry.terraform.io/hashicorp/aws",
        attributes=attributes,
    )
