"""Tools exposed to the LLM agent's tool-calling loop.

Every tool is sandboxed to the scan root: a path argument that resolves
outside ``root`` is rejected rather than followed. This matters for real —
not just symbolic — reasons, since these functions execute whatever path an
LLM decides to pass them, and this project's own rules.py flags exactly this
shape of bug (CWE-22, path traversal) in code under review.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .rules import scan_source
from .scanner import discover_python_files

MAX_READ_BYTES = 12_000
MAX_GREP_MATCHES = 50


class ToolError(Exception):
    """Raised when a tool call is invalid (bad path, unknown tool, ...)."""


def _resolve_within_root(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise ToolError(f"path '{relative}' escapes the scan root")
    return candidate


def list_python_files(root: str, path: str = ".") -> dict:
    root_path = Path(root)
    base = _resolve_within_root(root_path, path)
    if not base.is_dir():
        raise ToolError(f"'{path}' is not a directory")
    files = discover_python_files(base)
    return {"files": [str(f.relative_to(root_path.resolve())) for f in files]}


def read_file(root: str, path: str, max_bytes: int = MAX_READ_BYTES) -> dict:
    root_path = Path(root)
    target = _resolve_within_root(root_path, path)
    if not target.is_file():
        raise ToolError(f"'{path}' is not a file")
    text = target.read_text(encoding="utf-8", errors="replace")
    truncated = len(text) > max_bytes
    return {"path": path, "content": text[:max_bytes], "truncated": truncated}


def run_static_rules(root: str, path: str) -> dict:
    root_path = Path(root)
    target = _resolve_within_root(root_path, path)
    if not target.is_file():
        raise ToolError(f"'{path}' is not a file")
    try:
        source = target.read_text(encoding="utf-8", errors="replace")
        findings = scan_source(source, filename=path)
    except SyntaxError as exc:
        return {"path": path, "error": f"syntax error: {exc}", "findings": []}
    return {"path": path, "findings": [f.to_dict() for f in findings]}


def grep_pattern(root: str, pattern: str, path: str = ".", max_matches: int = MAX_GREP_MATCHES) -> dict:
    root_path = Path(root)
    base = _resolve_within_root(root_path, path)
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        raise ToolError(f"invalid regex: {exc}") from None

    matches: list[dict] = []
    files = discover_python_files(base) if base.is_dir() else [base]
    for file in files:
        if len(matches) >= max_matches:
            break
        text = file.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                matches.append({"path": str(file.relative_to(root_path.resolve())), "line": lineno, "text": line.strip()})
                if len(matches) >= max_matches:
                    break
    return {"matches": matches, "truncated": len(matches) >= max_matches}


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_python_files",
        "description": "List Python files under a directory (relative to the scan root).",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Directory to list, relative to the scan root. Defaults to the root itself."}},
        },
    },
    {
        "name": "read_file",
        "description": "Read the contents of a single file, relative to the scan root.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path relative to the scan root."}},
            "required": ["path"],
        },
    },
    {
        "name": "run_static_rules",
        "description": "Run the deterministic security rule engine against one Python file and "
        "return its findings (rule id, CWE, severity, line, remediation).",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path relative to the scan root."}},
            "required": ["path"],
        },
    },
    {
        "name": "grep_pattern",
        "description": "Search Python files under a directory for a regex pattern, returning matching lines.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regular expression to search for."},
                "path": {"type": "string", "description": "Directory to search, relative to the scan root. Defaults to the root."},
            },
            "required": ["pattern"],
        },
    },
]

_DISPATCH = {
    "list_python_files": list_python_files,
    "read_file": read_file,
    "run_static_rules": run_static_rules,
    "grep_pattern": grep_pattern,
}


def execute_tool(name: str, tool_input: dict, root: str) -> dict:
    """Dispatch a tool call by name, always returning a JSON-serializable dict.

    Errors are captured and returned as ``{"error": "..."}`` rather than
    raised, since this result is fed straight back to the model as a tool
    result — the loop should keep going with an error the model can react
    to, not crash the whole review.
    """
    handler = _DISPATCH.get(name)
    if handler is None:
        return {"error": f"unknown tool '{name}'"}
    try:
        return handler(root=root, **tool_input)
    except ToolError as exc:
        return {"error": str(exc)}
    except TypeError as exc:
        return {"error": f"invalid arguments for '{name}': {exc}"}
