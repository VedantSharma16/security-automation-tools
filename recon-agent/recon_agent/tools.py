"""The tool surface the agent (LLM or offline planner) operates over.

Each tool wraps one of the from-scratch recon primitives (DNS/HTTP/TLS),
matching the Anthropic `tools` schema shape so the same ``TOOL_SPECS`` list
can be handed straight to ``client.messages.create(tools=...)``. Every raw
finding is also kept on the registry (not just the JSON the LLM sees) so the
final report is built from ground-truth structured data, never from the
model's summary of what it did.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Callable

from . import dns_client, http_recon, tls_recon

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "dns_lookup",
        "description": (
            "Resolve a DNS record type for the target domain. Useful for mapping "
            "infrastructure (A/AAAA), mail setup (MX), SPF/DMARC/verification "
            "records (TXT), and authoritative nameservers (NS)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "record_type": {
                    "type": "string",
                    "enum": ["A", "AAAA", "MX", "TXT", "NS"],
                    "description": "DNS record type to query.",
                }
            },
            "required": ["record_type"],
        },
    },
    {
        "name": "http_headers",
        "description": (
            "Fetch the target's homepage over HTTP(S) and audit response "
            "headers for missing security headers (HSTS, CSP, X-Frame-Options, "
            "etc.) and server/stack fingerprinting headers."
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "robots_check",
        "description": (
            "Fetch robots.txt for the target and list Disallow paths and "
            "declared sitemaps. Disallowed paths often reveal admin panels, "
            "staging areas, or other paths not otherwise discoverable."
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "tls_check",
        "description": (
            "Connect over TLS and inspect the presented certificate: subject, "
            "issuer, SANs, expiry, negotiated protocol version and cipher. "
            "Flags expired/soon-to-expire certs and deprecated protocols."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "description": "TCP port to connect on.", "default": 443}
            },
        },
    },
]


class ToolError(Exception):
    """Raised when an unknown tool is dispatched."""


class ToolRegistry:
    """Executes recon tools against ``target_domain`` and records findings."""

    def __init__(
        self,
        target_domain: str,
        scheme: str = "https",
        dns_resolver: Callable[..., dns_client.DnsResult] = dns_client.resolve,
        http_opener=None,
        tls_connect=None,
    ):
        self.target_domain = target_domain
        self.base_url = f"{scheme}://{target_domain}"
        self._dns_resolver = dns_resolver
        self._http_opener = http_opener
        self._tls_connect = tls_connect

        self.dns_results: list[dns_client.DnsResult] = []
        self.http_finding: "http_recon.HttpFinding | None" = None
        self.robots_finding: "http_recon.RobotsFinding | None" = None
        self.tls_finding: "tls_recon.TlsFinding | None" = None

    def dns_lookup(self, record_type: str = "A") -> dict:
        result = self._dns_resolver(self.target_domain, record_type=record_type)
        self.dns_results.append(result)
        return asdict(result)

    def http_headers(self) -> dict:
        finding = http_recon.fetch_headers(self.base_url, opener=self._http_opener)
        self.http_finding = finding
        return asdict(finding)

    def robots_check(self) -> dict:
        finding = http_recon.fetch_robots(self.base_url, opener=self._http_opener)
        self.robots_finding = finding
        return asdict(finding)

    def tls_check(self, port: int = 443) -> dict:
        finding = tls_recon.check_tls(self.target_domain, port=port, connect=self._tls_connect)
        self.tls_finding = finding
        return asdict(finding)

    def dispatch(self, name: str, arguments: dict) -> dict:
        arguments = arguments or {}
        if name == "dns_lookup":
            return self.dns_lookup(record_type=arguments.get("record_type", "A"))
        if name == "http_headers":
            return self.http_headers()
        if name == "robots_check":
            return self.robots_check()
        if name == "tls_check":
            return self.tls_check(port=arguments.get("port", 443))
        raise ToolError(f"unknown tool: {name}")
