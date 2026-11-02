from __future__ import annotations

from collections import Counter, defaultdict

from .engine import LEVELS, Rule


def scan(rules: list[Rule], events) -> list[dict]:
    hits = []
    for idx, ev in enumerate(events, 1):
        for r in rules:
            if r.matches(ev):
                hits.append({"event_index": idx, "rule_id": r.id, "title": r.title,
                             "level": r.level, "techniques": r.techniques, "event": ev})
    return hits


def summarize(hits: list[dict]) -> dict:
    by_level = Counter(h["level"] for h in hits)
    by_tech = Counter(t for h in hits for t in h["techniques"])
    by_rule = Counter(h["rule_id"] for h in hits)
    return {"total": len(hits),
            "by_level": {l: by_level[l] for l in reversed(LEVELS) if by_level[l]},
            "by_technique": dict(by_tech.most_common()),
            "by_rule": dict(by_rule.most_common())}


def coverage(rules: list[Rule]) -> dict[str, list[str]]:
    cov = defaultdict(list)
    for r in rules:
        for t in r.techniques:
            cov[t].append(r.id)
    return dict(sorted(cov.items()))


def navigator_layer(rules: list[Rule], name: str = "detection-forge coverage") -> dict:
    """MITRE ATT&CK Navigator v4.5 layer; score = number of rules per technique."""
    return {"name": name, "versions": {"layer": "4.5"}, "domain": "enterprise-attack",
            "techniques": [{"techniqueID": t, "score": len(ids), "comment": ", ".join(ids)}
                           for t, ids in coverage(rules).items()]}
