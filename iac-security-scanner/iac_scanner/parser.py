"""Parsing `terraform show -json` plan output into a flat list of Resources.

Terraform plan JSON has two shapes we care about, and real-world plans only
ever populate one of them depending on how they were produced:

- ``resource_changes``: a flat list produced by ``terraform show -json
  <planfile>``. Each entry carries a ``change.after`` object with the
  resource's post-apply attribute values. This is the common case and the
  one CI pipelines usually feed in (``terraform plan -out=tf.plan &&
  terraform show -json tf.plan > plan.json``).
- ``planned_values.root_module``: a nested tree of modules/resources, each
  with a ``values`` object. Present on the same plan JSON but also usable
  on its own if only planned values were exported.

Resources being destroyed (``actions == ["delete"]``) are skipped since
there's nothing to audit going forward.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import IacScannerError, Resource


def parse_plan(path) -> list:
    """Load a `terraform show -json` file and return a list of Resources."""
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IacScannerError(f"{path} is not valid JSON: {exc}") from exc

    return parse_plan_dict(plan)


def parse_plan_dict(plan: dict) -> list:
    """Same as `parse_plan` but takes an already-decoded plan dict."""
    if not isinstance(plan, dict):
        raise IacScannerError("plan JSON must be an object")

    if "resource_changes" in plan:
        return list(_from_resource_changes(plan["resource_changes"] or []))

    root_module = plan.get("planned_values", {}).get("root_module")
    if root_module is not None:
        return list(_from_module(root_module))

    raise IacScannerError(
        "plan JSON has neither 'resource_changes' nor 'planned_values.root_module'; "
        "is this the output of `terraform show -json`?"
    )


def _from_resource_changes(resource_changes: list):
    for rc in resource_changes:
        actions = rc.get("change", {}).get("actions", [])
        if not actions or actions == ["delete"]:
            continue
        after = rc.get("change", {}).get("after")
        if after is None:
            continue
        yield Resource(
            address=rc["address"],
            type=rc["type"],
            name=rc["name"],
            mode=rc.get("mode", "managed"),
            provider_name=rc.get("provider_name", ""),
            attributes=after,
        )


def _from_module(module: dict):
    for res in module.get("resources", []):
        yield Resource(
            address=res["address"],
            type=res["type"],
            name=res["name"],
            mode=res.get("mode", "managed"),
            provider_name=res.get("provider_name", ""),
            attributes=res.get("values") or {},
        )
    for child in module.get("child_modules", []):
        yield from _from_module(child)
