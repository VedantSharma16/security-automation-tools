"""The tools available to the agent: local, offline, deterministic lookups.

Each tool takes a single string input and returns a :class:`~ir_agent.models.ToolResult`.
Keeping them pure and offline means the agent's *decisions* (which tools to call,
in what order, when to stop) can be tested independently of any LLM or network access.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ir_agent.models import ToolResult

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9]+")


def _load_json(name: str) -> dict:
    with open(DATA_DIR / name, encoding="utf-8") as handle:
        return json.load(handle)


@dataclass
class IntelStore:
    """In-memory index over the bundled threat-intel and reference data."""

    malicious_ips: dict[str, dict] = field(default_factory=dict)
    malicious_domains: dict[str, dict] = field(default_factory=dict)
    cves: dict[str, dict] = field(default_factory=dict)
    techniques: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, data_dir: Path | None = None) -> "IntelStore":
        base = data_dir or DATA_DIR

        def load(name: str) -> dict:
            with open(base / name, encoding="utf-8") as handle:
                return json.load(handle)

        ip_data = load("known_malicious_ips.json")
        domain_data = load("known_malicious_domains.json")
        cve_data = load("cve_db.json")
        technique_data = load("mitre_attack_techniques.json")

        return cls(
            malicious_ips={e["ip"]: e for e in ip_data.get("indicators", [])},
            malicious_domains={e["domain"]: e for e in domain_data.get("indicators", [])},
            cves={c["id"].upper(): c for c in cve_data.get("cves", [])},
            techniques=technique_data.get("techniques", []),
        )


_DEFAULT_STORE: IntelStore | None = None


def default_store() -> IntelStore:
    global _DEFAULT_STORE
    if _DEFAULT_STORE is None:
        _DEFAULT_STORE = IntelStore.load()
    return _DEFAULT_STORE


def check_ip_reputation(ip: str, store: IntelStore | None = None) -> ToolResult:
    store = store or default_store()
    hit = store.malicious_ips.get(ip)
    if hit:
        return ToolResult(
            tool="check_ip_reputation",
            tool_input=ip,
            malicious=True,
            summary=f"{ip} is a known-malicious indicator ({hit['confidence']} confidence): {hit['notes']}",
            detail=hit,
        )
    return ToolResult(
        tool="check_ip_reputation",
        tool_input=ip,
        malicious=False,
        summary=f"{ip} did not match any entry in the local threat-intel feed.",
        detail={},
    )


def check_domain_reputation(domain: str, store: IntelStore | None = None) -> ToolResult:
    store = store or default_store()
    hit = store.malicious_domains.get(domain)
    if hit:
        return ToolResult(
            tool="check_domain_reputation",
            tool_input=domain,
            malicious=True,
            summary=f"{domain} is a known-malicious indicator ({hit['confidence']} confidence): {hit['notes']}",
            detail=hit,
        )
    return ToolResult(
        tool="check_domain_reputation",
        tool_input=domain,
        malicious=False,
        summary=f"{domain} did not match any entry in the local threat-intel feed.",
        detail={},
    )


def check_cve(cve_id: str, store: IntelStore | None = None) -> ToolResult:
    store = store or default_store()
    cve_id = cve_id.upper()
    hit = store.cves.get(cve_id)
    if hit:
        exploited = " It is listed as known-exploited in the wild." if hit["known_exploited"] else ""
        return ToolResult(
            tool="check_cve",
            tool_input=cve_id,
            malicious=bool(hit["known_exploited"] or hit["severity"] in ("critical", "high")),
            summary=(
                f"{cve_id} ({hit['name']}) has CVSS {hit['cvss']}, severity {hit['severity']}."
                f"{exploited}"
            ),
            detail=hit,
        )
    return ToolResult(
        tool="check_cve",
        tool_input=cve_id,
        malicious=False,
        summary=f"{cve_id} was not found in the local CVE database; severity unknown.",
        detail={},
    )


def _tokenize(text: str) -> Counter:
    return Counter(t.lower() for t in _TOKEN_RE.findall(text))


def lookup_attack_technique(query: str, store: IntelStore | None = None) -> ToolResult:
    """Score bundled ATT&CK techniques against ``query`` by keyword overlap."""
    store = store or default_store()
    query_tokens = set(_tokenize(query))

    best: dict | None = None
    best_score = 0
    for technique in store.techniques:
        keyword_tokens: set[str] = set()
        for kw in technique["keywords"]:
            keyword_tokens.update(_tokenize(kw))
        score = len(query_tokens & keyword_tokens)
        if score > best_score:
            best_score = score
            best = technique

    if best is None or best_score == 0:
        return ToolResult(
            tool="lookup_attack_technique",
            tool_input=query[:120],
            malicious=False,
            summary="No ATT&CK technique keywords matched the incident text with any confidence.",
            detail={},
        )
    return ToolResult(
        tool="lookup_attack_technique",
        tool_input=query[:120],
        malicious=False,
        summary=(
            f"Incident language most closely matches {best['id']} {best['name']} "
            f"(tactic: {best['tactic']}), keyword overlap score {best_score}."
        ),
        detail={**best, "match_score": best_score},
    )


TOOL_FUNCTIONS = {
    "check_ip_reputation": check_ip_reputation,
    "check_domain_reputation": check_domain_reputation,
    "check_cve": check_cve,
    "lookup_attack_technique": lookup_attack_technique,
}
