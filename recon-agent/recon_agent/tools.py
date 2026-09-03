"""Tool schemas (Claude tool-use format) and the dispatcher that executes them.

This is the seam between the LLM-facing agent loop in ``agent.py`` and the
actual recon implementations. Keeping it separate means the tool schemas,
their execution, and the orchestration loop can each be tested in
isolation.
"""

from __future__ import annotations

from . import dns_recon, http_fingerprint, port_scan

TOOL_SCHEMAS = [
    {
        "name": "resolve_and_enumerate_subdomains",
        "description": (
            "Resolve the target domain's IP address and enumerate common subdomains "
            "against it using a built-in wordlist. Use this first for a domain target."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Target domain, e.g. example.com"}},
            "required": ["domain"],
        },
    },
    {
        "name": "scan_ports",
        "description": "TCP connect-scan a host across a curated list of commonly interesting ports.",
        "input_schema": {
            "type": "object",
            "properties": {"host": {"type": "string", "description": "Hostname or IP address to scan."}},
            "required": ["host"],
        },
    },
    {
        "name": "fingerprint_web_services",
        "description": (
            "Fetch HTTP response headers, the page title, and TLS certificate expiry "
            "for the given host on the given list of open web ports."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "ports": {"type": "array", "items": {"type": "integer"}},
            },
            "required": ["host", "ports"],
        },
    },
]


def dispatch(name: str, tool_input: dict, *, wordlist: list[str], ports_list: list[int]) -> dict:
    """Execute one tool call and return a JSON-serializable result dict."""
    if name == "resolve_and_enumerate_subdomains":
        domain = tool_input["domain"]
        return {
            "domain": domain,
            "ip": dns_recon.resolve(domain),
            "subdomains": dns_recon.enumerate_subdomains(domain, wordlist),
        }

    if name == "scan_ports":
        host = tool_input["host"]
        results = port_scan.scan_ports(host, ports=ports_list)
        return {"host": host, "open_ports": [r.__dict__ for r in results]}

    if name == "fingerprint_web_services":
        host = tool_input["host"]
        ports = tool_input["ports"]
        fingerprints = [http_fingerprint.fingerprint_http(host, port) for port in ports]
        return {"host": host, "fingerprints": [fp.__dict__ for fp in fingerprints]}

    raise ValueError(f"Unknown tool: {name}")
