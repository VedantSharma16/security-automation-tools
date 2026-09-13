"""Tool definitions the investigating agent can call.

Each tool is described by an Anthropic-style JSON schema (name, description,
input_schema) plus a plain Python function that executes it against an
:class:`~agent.environment.Environment`. The schemas are reused verbatim for
the live Claude tool-use loop and for validating/dispatching the offline
planner's choices, so both code paths exercise the same tool surface.
"""

from __future__ import annotations

from typing import Any, Callable

from .environment import Environment, UnknownHostError

TOOL_SCHEMAS: list[dict] = [
    {
        "name": "search_logs",
        "description": (
            "Search authentication/system log lines for a given host, optionally "
            "filtered by a substring query. Use this first to understand what "
            "happened around the time of the alert."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname to search."},
                "query": {
                    "type": "string",
                    "description": "Optional substring to filter log lines by (case-insensitive).",
                },
            },
            "required": ["host"],
        },
    },
    {
        "name": "lookup_ioc",
        "description": (
            "Check an indicator (IP address, domain, or SHA-256 hash) against the "
            "local threat-intel feed to see whether it is known-malicious."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "The indicator value to look up."},
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "get_process_list",
        "description": "List the running processes on a host, including PIDs and command lines.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname to inspect."},
            },
            "required": ["host"],
        },
    },
    {
        "name": "get_process_detail",
        "description": (
            "Get full detail (command line, parent PID, SHA-256 hash) for a single "
            "process on a host, identified by PID."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname to inspect."},
                "pid": {"type": "integer", "description": "Process ID to inspect."},
            },
            "required": ["host", "pid"],
        },
    },
]

TOOL_NAMES = {schema["name"] for schema in TOOL_SCHEMAS}


class ToolError(Exception):
    """Raised when a tool is called with bad arguments."""


def _search_logs(env: Environment, args: dict) -> dict:
    host = args["host"]
    query = args.get("query")
    lines = env.search_logs(host, query)
    return {"host": host, "query": query, "matched_lines": lines, "count": len(lines)}


def _lookup_ioc(env: Environment, args: dict) -> dict:
    return env.lookup_ioc(args["indicator"])


def _get_process_list(env: Environment, args: dict) -> dict:
    host = args["host"]
    return {"host": host, "processes": env.get_process_list(host)}


def _get_process_detail(env: Environment, args: dict) -> dict:
    host, pid = args["host"], int(args["pid"])
    proc = env.get_process_detail(host, pid)
    if proc is None:
        return {"host": host, "pid": pid, "found": False}
    return {"host": host, "pid": pid, "found": True, "process": proc}


_DISPATCH: dict[str, Callable[[Environment, dict], dict]] = {
    "search_logs": _search_logs,
    "lookup_ioc": _lookup_ioc,
    "get_process_list": _get_process_list,
    "get_process_detail": _get_process_detail,
}


def execute_tool(name: str, args: dict[str, Any], env: Environment) -> dict:
    """Run a single tool call and return its JSON-serializable observation."""
    if name not in _DISPATCH:
        raise ToolError(f"unknown tool: {name}")
    try:
        return _DISPATCH[name](env, args)
    except UnknownHostError as exc:
        raise ToolError(f"unknown host: {exc}") from exc
    except KeyError as exc:
        raise ToolError(f"missing required argument: {exc}") from exc
