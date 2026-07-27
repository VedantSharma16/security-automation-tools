"""Investigative "tools" the agent can call.

Each tool is a plain, pure Python function over a small local JSON dataset
under ``data/`` — standing in for the internal systems a real triage agent
would query (asset inventory / CMDB, a threat-intel feed, an IdP risk
signal, an EDR process baseline). Keeping them as plain functions means the
exact same implementations back both the offline deterministic planner and
the live Claude tool-use loop, so the two modes can never silently diverge
in what a given lookup returns.

``TOOL_SCHEMAS`` describes them in Anthropic tool-use ``input_schema``
format; ``TOOL_IMPLEMENTATIONS`` maps a tool name to a callable that takes
the raw ``dict`` of arguments the model supplied.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load(name: str) -> dict:
    return json.loads((DATA_DIR / name).read_text())


@functools.lru_cache(maxsize=1)
def _asset_inventory() -> dict:
    return _load("asset_inventory.json")


@functools.lru_cache(maxsize=1)
def _ioc_reputation() -> dict:
    return _load("ioc_reputation.json")


@functools.lru_cache(maxsize=1)
def _user_risk() -> dict:
    return _load("user_risk.json")


@functools.lru_cache(maxsize=1)
def _process_baselines() -> dict:
    return _load("process_baselines.json")


def lookup_asset_criticality(hostname: str) -> dict:
    """Look up an internal asset's business-criticality tier and owner."""
    info = _asset_inventory().get(hostname)
    if info is None:
        return {"hostname": hostname, "known_asset": False, "criticality": "unknown", "owner": None}
    return {"hostname": hostname, "known_asset": True, **info}


def lookup_ioc_reputation(indicator: str) -> dict:
    """Check an IP/domain indicator against the local threat-intel feed."""
    info = _ioc_reputation().get(indicator)
    if info is None:
        return {"indicator": indicator, "known": False, "verdict": "unknown", "source": None, "notes": None}
    return {"indicator": indicator, "known": True, **info}


def lookup_user_risk(username: str) -> dict:
    """Check a username against the identity provider's risk signal."""
    info = _user_risk().get(username)
    if info is None:
        return {
            "username": username,
            "known_user": False,
            "anomalous": False,
            "failed_logins_24h": 0,
            "privilege": "unknown",
        }
    return {"username": username, "known_user": True, **info}


def check_process_baseline(hostname: str, process_name: str) -> dict:
    """Check whether a process is on the known-good baseline for a host."""
    baseline = _process_baselines().get(hostname)
    if baseline is None:
        return {
            "hostname": hostname,
            "process_name": process_name,
            "host_has_baseline": False,
            "is_baselined": None,
        }
    return {
        "hostname": hostname,
        "process_name": process_name,
        "host_has_baseline": True,
        "is_baselined": process_name in baseline,
    }


TOOL_IMPLEMENTATIONS = {
    "lookup_asset_criticality": lambda args: lookup_asset_criticality(args["hostname"]),
    "lookup_ioc_reputation": lambda args: lookup_ioc_reputation(args["indicator"]),
    "lookup_user_risk": lambda args: lookup_user_risk(args["username"]),
    "check_process_baseline": lambda args: check_process_baseline(args["hostname"], args["process_name"]),
}

TOOL_SCHEMAS = [
    {
        "name": "lookup_asset_criticality",
        "description": "Look up the business criticality tier (crown_jewel/standard/low) and owning "
        "team for an internal asset by hostname.",
        "input_schema": {
            "type": "object",
            "properties": {"hostname": {"type": "string", "description": "The asset hostname."}},
            "required": ["hostname"],
        },
    },
    {
        "name": "lookup_ioc_reputation",
        "description": "Check an IP address or domain against the internal threat-intel feed for a "
        "known-malicious / suspicious / clean verdict.",
        "input_schema": {
            "type": "object",
            "properties": {"indicator": {"type": "string", "description": "The IP address or domain to check."}},
            "required": ["indicator"],
        },
    },
    {
        "name": "lookup_user_risk",
        "description": "Look up a user's identity-provider risk signal: whether their recent activity is "
        "flagged anomalous, their failed-login count in the last 24h, and their privilege level.",
        "input_schema": {
            "type": "object",
            "properties": {"username": {"type": "string", "description": "The username to check."}},
            "required": ["username"],
        },
    },
    {
        "name": "check_process_baseline",
        "description": "Check whether a process name is on the known-good EDR baseline for a given host.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string"},
                "process_name": {"type": "string"},
            },
            "required": ["hostname", "process_name"],
        },
    },
]
