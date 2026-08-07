"""The agent's tool belt.

Each tool is a plain Python function that takes JSON-serializable arguments
and returns a JSON-serializable observation. ``TOOL_SCHEMAS`` describes them
in Anthropic tool-use / JSON Schema form so the same definitions drive both
the live LLM tool-calling loop and this module's docs/tests — the schema is
never hand-duplicated between the two.

All data backing these tools is a small synthetic, offline dataset under
``data/`` (see that directory's ``_comment`` fields). Swapping in a real
threat-intel feed, WHOIS API, or GeoIP database means only touching the
``_load_json`` calls below — the tool signatures and the agent loop are
unaffected.
"""

from __future__ import annotations

import datetime
import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "is",
    "are", "was", "were", "with", "by", "at", "from", "this", "that",
}


def _load_json(name: str) -> dict:
    with open(DATA_DIR / name, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _tokenize(text: str) -> set:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {w for w in words if w not in _STOPWORDS}


def lookup_ip_reputation(ip: str) -> dict:
    """Check an IPv4 address against the local threat-intel feed."""
    feed = _load_json("ip_reputation.json")
    hit = feed.get(ip)
    if hit is None:
        return {"ip": ip, "verdict": "unknown", "confidence": "low", "notes": "No local threat-intel record.", "source": "internal-blocklist"}
    return {"ip": ip, **hit}


def lookup_domain_reputation(domain: str) -> dict:
    """Check a domain against the local threat-intel feed."""
    feed = _load_json("domain_reputation.json")
    domain = domain.lower()
    hit = feed.get(domain)
    if hit is None:
        return {"domain": domain, "verdict": "unknown", "confidence": "low", "notes": "No local threat-intel record.", "source": "internal-blocklist"}
    return {"domain": domain, **hit}


def geoip_lookup(ip: str) -> dict:
    """Look up coarse geolocation/ASN info for an IPv4 address."""
    data = _load_json("geoip_stub.json")["records"]
    hit = data.get(ip)
    if hit is None:
        return {"ip": ip, "country": "unknown", "asn": "unknown", "asn_org": "unknown"}
    return {"ip": ip, **hit}


def whois_lookup(domain: str) -> dict:
    """Look up synthetic WHOIS registration info for a domain, including
    domain age in days (a strong phishing/C2-infrastructure signal — newly
    registered domains are disproportionately used in active campaigns)."""
    data = _load_json("whois_stub.json")["records"]
    domain = domain.lower()
    hit = data.get(domain)
    if hit is None:
        return {"domain": domain, "registrar": "unknown", "created": None, "age_days": None, "privacy_protected": None, "notes": "No WHOIS record available."}
    created = datetime.date.fromisoformat(hit["created"])
    age_days = (datetime.date.today() - created).days
    return {
        "domain": domain,
        "registrar": hit["registrar"],
        "created": hit["created"],
        "age_days": age_days,
        "privacy_protected": hit["privacy_protected"],
    }


def check_process_baseline(process_name: str) -> dict:
    """Check whether a process name is a known-good baseline process, a
    known-bad/high-risk tool, or unrecognized."""
    baseline = _load_json("process_baseline.json")
    name = process_name.lower().strip()
    if name in baseline["known_bad"]:
        return {"process_name": name, "status": "known_bad", "notes": baseline["known_bad"][name]}
    if name in {p.lower() for p in baseline["known_good"]}:
        return {"process_name": name, "status": "known_good", "notes": "Matches expected baseline process."}
    return {"process_name": name, "status": "unrecognized", "notes": "Not present in the baseline; treat with default suspicion."}


def search_attack_techniques(query: str, top_k: int = 3) -> list:
    """Keyword-overlap search over a curated MITRE ATT&CK technique subset.
    Returns the top_k techniques ranked by token overlap with the query."""
    techniques = _load_json("attack_techniques.json")["techniques"]
    query_tokens = _tokenize(query)
    scored = []
    for tech in techniques:
        tech_tokens = _tokenize(f"{tech['name']} {tech['text']} {tech['tactic']}")
        overlap = query_tokens & tech_tokens
        if not overlap:
            continue
        score = len(overlap) / len(query_tokens | tech_tokens)
        scored.append((score, tech))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [
        {"id": t["id"], "name": t["name"], "tactic": t["tactic"], "text": t["text"], "relevance": round(score, 3)}
        for score, t in scored[:top_k]
    ]


TOOL_FUNCTIONS = {
    "lookup_ip_reputation": lookup_ip_reputation,
    "lookup_domain_reputation": lookup_domain_reputation,
    "geoip_lookup": geoip_lookup,
    "whois_lookup": whois_lookup,
    "check_process_baseline": check_process_baseline,
    "search_attack_techniques": search_attack_techniques,
}

TOOL_SCHEMAS = [
    {
        "name": "lookup_ip_reputation",
        "description": "Check an IPv4 address against the local threat-intel feed for known-malicious or suspicious activity.",
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IPv4 address, e.g. 185.220.101.1"}},
            "required": ["ip"],
        },
    },
    {
        "name": "lookup_domain_reputation",
        "description": "Check a domain name against the local threat-intel feed for known-malicious or suspicious activity.",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Domain name, e.g. evil-c2-panel.com"}},
            "required": ["domain"],
        },
    },
    {
        "name": "geoip_lookup",
        "description": "Look up coarse geolocation and ASN/hosting-provider info for an IPv4 address.",
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IPv4 address"}},
            "required": ["ip"],
        },
    },
    {
        "name": "whois_lookup",
        "description": "Look up WHOIS registration info for a domain, including its age in days. Newly registered domains are a strong phishing/C2 signal.",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Domain name"}},
            "required": ["domain"],
        },
    },
    {
        "name": "check_process_baseline",
        "description": "Check whether a process name is a known-good baseline process, a known-bad/high-risk tool (e.g. mimikatz), or unrecognized.",
        "input_schema": {
            "type": "object",
            "properties": {"process_name": {"type": "string", "description": "Process name, e.g. powershell.exe"}},
            "required": ["process_name"],
        },
    },
    {
        "name": "search_attack_techniques",
        "description": "Search a curated MITRE ATT&CK technique subset by keyword to find techniques matching observed behavior (e.g. 'encoded powershell scheduled task').",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Free-text description of the observed behavior"},
                "top_k": {"type": "integer", "description": "Number of techniques to return", "default": 3},
            },
            "required": ["query"],
        },
    },
]
