"""Load the attack-probe and benign-prompt corpora from ``data/``."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

OWASP_LLM_TOP10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
}

DETECTORS = {"marker", "canary", "prompt_leak", "exfil", "tool_abuse"}


@dataclass(frozen=True)
class Probe:
    id: str
    category: str
    owasp: tuple[str, ...]
    technique: str
    user: str
    documents: tuple[str, ...] = ()
    detectors: tuple[str, ...] = ("marker",)
    benign: bool = False
    notes: str = ""

    def materialize(self, scenario) -> tuple[str, list[str]]:
        """Fill scenario placeholders, *then* apply obfuscation macros, so that
        e.g. a base64-encoded payload contains the real per-run marker."""
        user = expand(scenario.render(self.user))
        docs = [expand(scenario.render(d)) for d in self.documents]
        return user, docs


@dataclass
class ProbeSet:
    probes: list[Probe] = field(default_factory=list)

    def categories(self) -> list[str]:
        return sorted({p.category for p in self.probes})

    def filter(self, categories: list[str] | None) -> "ProbeSet":
        if not categories:
            return self
        wanted = set(categories)
        return ProbeSet([p for p in self.probes if p.category in wanted])


def expand(text: str) -> str:
    """Support ``{b64:...}`` so obfuscated payloads stay readable in the JSON."""
    while "{b64:" in text:
        start = text.index("{b64:")
        end = text.index(":b64}", start)
        inner = text[start + 5 : end]
        text = text[:start] + base64.b64encode(inner.encode()).decode() + text[end + 5 :]
    return text.replace("{ZWSP}", "​")


def _parse(entry: dict, benign: bool) -> Probe:
    detectors = tuple(entry.get("detectors", [] if benign else ["marker"]))
    unknown = set(detectors) - DETECTORS
    if unknown:
        raise ValueError(f"probe {entry['id']}: unknown detector(s) {sorted(unknown)}")
    return Probe(
        id=entry["id"],
        category=entry.get("category", "benign" if benign else "uncategorized"),
        owasp=tuple(entry.get("owasp", [])),
        technique=entry.get("technique", ""),
        user=entry["user"],
        documents=tuple(entry.get("documents", [])),
        detectors=detectors,
        benign=benign,
        notes=entry.get("notes", ""),
    )


def load_probes(path: Path | None = None) -> ProbeSet:
    data = json.loads((path or DATA_DIR / "probes.json").read_text())
    return ProbeSet([_parse(e, benign=False) for e in data])


def load_benign(path: Path | None = None) -> ProbeSet:
    data = json.loads((path or DATA_DIR / "benign.json").read_text())
    return ProbeSet([_parse(e, benign=True) for e in data])
