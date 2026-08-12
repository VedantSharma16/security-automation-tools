"""Investigation tools available to the agent.

Each tool is a plain Python function operating on small local JSON
datasets under ``data/`` — a self-contained stand-in for the real systems
an analyst would query (a TIP, DNS/WHOIS, a SIEM, a CMDB). Every tool is
also described by an Anthropic tool-use JSON schema in ``TOOL_SCHEMAS`` so
the same functions back both the live LLM tool-calling loop
(:mod:`soc_agent.agent`) and the deterministic offline planner
(:mod:`soc_agent.planner`).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")

# A domain-shaped regex also matches filenames (explorer.exe) and dotted
# usernames (j.morales). Restricting matches to a known-TLD allowlist trades
# a little recall on obscure TLDs for much better precision on alert text.
_ALLOWED_TLDS = {
    "com", "net", "org", "io", "co", "biz", "info", "gov", "edu", "mil",
    "int", "internal", "local", "dev", "app", "cloud", "ai",
}


def _load_json(name: str) -> dict:
    with open(DATA_DIR / name, encoding="utf-8") as handle:
        return json.load(handle)


def extract_indicators(text: str) -> dict:
    """Pull candidate IPs and domains out of free-text alert content."""
    ips = sorted(set(_IP_RE.findall(text)))
    candidates = set(_DOMAIN_RE.findall(text)) - set(ips)
    domains = sorted(d for d in candidates if d.rsplit(".", 1)[-1].lower() in _ALLOWED_TLDS)
    return {"ips": ips, "domains": domains}


def ioc_lookup(indicator: str) -> dict:
    """Check an indicator (IP, domain, or hash) against the local threat-intel feed."""
    feed = _load_json("threat_intel.json")["indicators"]
    for entry in feed:
        if entry["value"].lower() == indicator.lower():
            return {"indicator": indicator, "found": True, **{k: v for k, v in entry.items() if k != "value"}}
    return {"indicator": indicator, "found": False, "verdict": "unknown", "confidence": "n/a", "notes": "No match in local threat-intel feed."}


def dns_lookup(domain: str) -> dict:
    """Resolve a domain's DNS/registration metadata from the local mock resolver."""
    records = _load_json("dns_records.json")
    hit = records.get(domain)
    if hit is None:
        return {"domain": domain, "found": False, "notes": "No record for this domain in the mock resolver."}
    return {"domain": domain, "found": True, **hit}


def mitre_lookup(keyword: str) -> dict:
    """Find MITRE ATT&CK techniques whose keywords match the given phrase."""
    techniques = _load_json("mitre_techniques.json")["techniques"]
    keyword_lower = keyword.lower()
    matches = [
        {"id": t["id"], "name": t["name"], "tactic": t["tactic"], "description": t["description"]}
        for t in techniques
        if any(kw in keyword_lower or keyword_lower in kw for kw in t["keywords"])
    ]
    return {"keyword": keyword, "matches": matches}


def search_logs(query: str) -> dict:
    """Grep the sample log corpus for lines containing the query string."""
    log_path = DATA_DIR / "sample_logs" / "auth.log"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    hits = [line for line in lines if query.lower() in line.lower()]
    return {"query": query, "match_count": len(hits), "lines": hits}


def get_asset_criticality(hostname: str) -> dict:
    """Look up business criticality and ownership for a hostname from the asset inventory."""
    inventory = _load_json("asset_inventory.json")
    hit = inventory.get(hostname)
    if hit is None:
        return {"hostname": hostname, "found": False, "criticality": "unknown"}
    return {"hostname": hostname, "found": True, **hit}


TOOLS = {
    "ioc_lookup": ioc_lookup,
    "dns_lookup": dns_lookup,
    "mitre_lookup": mitre_lookup,
    "search_logs": search_logs,
    "get_asset_criticality": get_asset_criticality,
}

# Anthropic tool-use schemas. `submit_verdict` is not a real lookup tool —
# calling it is how the model signals "investigation complete" and hands
# back its structured conclusion, ending the agent loop.
TOOL_SCHEMAS = [
    {
        "name": "ioc_lookup",
        "description": "Check an indicator of compromise (IP, domain, or file hash) against the local threat-intel feed.",
        "input_schema": {
            "type": "object",
            "properties": {"indicator": {"type": "string", "description": "The IP, domain, or hash to look up."}},
            "required": ["indicator"],
        },
    },
    {
        "name": "dns_lookup",
        "description": "Resolve DNS/registration metadata (A records, registrar, domain age) for a domain.",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "The domain to resolve."}},
            "required": ["domain"],
        },
    },
    {
        "name": "mitre_lookup",
        "description": "Find MITRE ATT&CK techniques related to a keyword or phrase describing observed behavior.",
        "input_schema": {
            "type": "object",
            "properties": {"keyword": {"type": "string", "description": "A behavior keyword, e.g. 'beaconing' or 'phishing'."}},
            "required": ["keyword"],
        },
    },
    {
        "name": "search_logs",
        "description": "Search the SOC's log corpus for lines matching a query (IP, username, hostname, etc.).",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Substring to search for in the logs."}},
            "required": ["query"],
        },
    },
    {
        "name": "get_asset_criticality",
        "description": "Look up business criticality and ownership for a hostname from the asset inventory.",
        "input_schema": {
            "type": "object",
            "properties": {"hostname": {"type": "string", "description": "The hostname to look up."}},
            "required": ["hostname"],
        },
    },
    {
        "name": "submit_verdict",
        "description": "Submit the final triage verdict once you have gathered enough evidence. This ends the investigation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign", "inconclusive"]},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "recommended_action": {"type": "string"},
                "rationale": {"type": "string"},
            },
            "required": ["verdict", "confidence", "recommended_action", "rationale"],
        },
    },
]
