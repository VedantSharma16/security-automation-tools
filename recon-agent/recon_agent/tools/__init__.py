"""Recon tools plus a registry that binds each one to a scan target."""
from __future__ import annotations

from typing import Callable, Dict

from ..models import ToolResult
from . import dns_tool, headers_tool, robots_tool, tls_tool


def build_registry(target: str) -> Dict[str, Callable[[], ToolResult]]:
    """Bind every tool to `target` so the planner can call each one with no args."""
    url = headers_tool.normalize_url(target)
    return {
        "dns_lookup": lambda: dns_tool.run(target),
        "http_headers": lambda: headers_tool.run(url),
        "tls_certificate": lambda: tls_tool.run(target),
        "robots_txt": lambda: robots_tool.run(url),
    }
