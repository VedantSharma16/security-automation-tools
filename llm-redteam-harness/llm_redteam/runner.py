"""Campaign execution and aggregation."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from llm_redteam.attacks import OWASP_LLM_TOP10, SEVERITY_ORDER, Attack, new_marker
from llm_redteam.judge import judge, looks_like_refusal


@dataclass
class AttackResult:
    attack_id: str
    name: str
    category: str
    owasp: str
    severity: str
    goal: str
    delivery: str
    success: bool
    evidence: str
    refused: bool
    response_excerpt: str
    latency_ms: int
    error: str | None = None


@dataclass
class CampaignReport:
    target: str
    started_at: str
    results: list[AttackResult] = field(default_factory=list)
    defence_events: list[str] = field(default_factory=list)

    @property
    def completed(self) -> list[AttackResult]:
        return [r for r in self.results if r.error is None]

    @property
    def successes(self) -> list[AttackResult]:
        return [r for r in self.results if r.success]

    @property
    def attack_success_rate(self) -> float:
        done = self.completed
        return len([r for r in done if r.success]) / len(done) if done else 0.0

    @property
    def worst_severity(self) -> str:
        if not self.successes:
            return "info"
        return max((r.severity for r in self.successes), key=SEVERITY_ORDER.index)

    def breakdown(self, key: str) -> dict[str, dict]:
        buckets: dict[str, list[AttackResult]] = defaultdict(list)
        for r in self.completed:
            buckets[getattr(r, key)].append(r)
        out = {}
        for k in sorted(buckets):
            items = buckets[k]
            wins = sum(r.success for r in items)
            entry = {"attempted": len(items), "succeeded": wins, "asr": round(wins / len(items), 3)}
            if key == "owasp":
                entry["title"] = OWASP_LLM_TOP10.get(k, "")
            out[k] = entry
        return out

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "summary": {
                "attacks": len(self.results),
                "completed": len(self.completed),
                "errors": len(self.results) - len(self.completed),
                "succeeded": len(self.successes),
                "attack_success_rate": round(self.attack_success_rate, 3),
                "worst_severity": self.worst_severity,
            },
            "by_category": self.breakdown("category"),
            "by_owasp": self.breakdown("owasp"),
            "results": [asdict(r) for r in self.results],
            "defence_events": self.defence_events,
        }


def run_campaign(target, attacks: list[Attack], marker_factory=new_marker,
                 excerpt_chars: int = 240, clock=time.perf_counter) -> CampaignReport:
    report = CampaignReport(target=target.name, started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    for attack in attacks:
        rendered = attack.render(marker_factory())
        start = clock()
        try:
            response = target.respond(rendered.user_message, rendered.documents)
            error = None
        except Exception as exc:  # a broken target must not abort the whole campaign
            response, error = "", f"{type(exc).__name__}: {exc}"
        latency = int((clock() - start) * 1000)

        if error:
            verdict_success, evidence = False, "target error"
        else:
            verdict = judge(attack.goal, response, marker=rendered.marker,
                            canary=target.canary, system_prompt=target.system_prompt)
            verdict_success, evidence = verdict.success, verdict.evidence

        excerpt = response.replace(target.canary, "<CANARY>") if target.canary else response
        report.results.append(AttackResult(
            attack_id=attack.id, name=attack.name, category=attack.category, owasp=attack.owasp,
            severity=attack.severity, goal=attack.goal, delivery=attack.delivery,
            success=verdict_success, evidence=evidence,
            refused=bool(response) and not verdict_success and looks_like_refusal(response),
            response_excerpt=excerpt[:excerpt_chars], latency_ms=latency, error=error,
        ))

    report.defence_events = list(getattr(target, "events", []))
    return report
