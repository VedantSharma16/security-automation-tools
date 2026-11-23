"""Run a probe corpus against a target and compute attack-success metrics."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field

from .canary import new_canary
from .evaluators import evaluate
from .models import Scenario, TargetRequest
from .probes import Probe, ProbeSet


def new_scenario() -> Scenario:
    """Fresh secrets per run, so a leak can never be a cached/memorized string."""
    return Scenario(canary=new_canary("CANARY"), marker=new_canary("PWNED"))


@dataclass
class ProbeResult:
    probe_id: str
    category: str
    owasp: list[str]
    technique: str
    benign: bool
    success: bool  # attack achieved its goal (always False for benign prompts)
    evidence: dict[str, str]
    intervened: str | None  # guardrail stage that acted, if any
    guardrail_notes: list[str]
    response_excerpt: str
    tool_calls: list[dict]
    error: str | None = None


@dataclass
class RunResult:
    target: str
    results: list[ProbeResult] = field(default_factory=list)

    @property
    def attacks(self) -> list[ProbeResult]:
        return [r for r in self.results if not r.benign]

    @property
    def benign(self) -> list[ProbeResult]:
        return [r for r in self.results if r.benign]

    @staticmethod
    def _rate(hits: int, total: int) -> float:
        return round(hits / total, 3) if total else 0.0

    def attack_success_rate(self) -> float:
        return self._rate(sum(r.success for r in self.attacks), len(self.attacks))

    def asr_by(self, key: str) -> dict[str, dict]:
        buckets: dict[str, list[ProbeResult]] = defaultdict(list)
        for r in self.attacks:
            values = r.owasp if key == "owasp" else [getattr(r, key)]
            for value in values:
                buckets[value].append(r)
        return {
            k: {"total": len(v), "successful": sum(r.success for r in v),
                "asr": self._rate(sum(r.success for r in v), len(v))}
            for k, v in sorted(buckets.items())
        }

    def false_positive_rate(self) -> float:
        return self._rate(sum(r.intervened is not None for r in self.benign), len(self.benign))

    def summary(self) -> dict:
        return {
            "target": self.target,
            "attacks": len(self.attacks),
            "successful_attacks": sum(r.success for r in self.attacks),
            "attack_success_rate": self.attack_success_rate(),
            "benign_prompts": len(self.benign),
            "guardrail_false_positive_rate": self.false_positive_rate(),
            "by_category": self.asr_by("category"),
            "by_owasp": self.asr_by("owasp"),
        }

    def to_dict(self) -> dict:
        return {"summary": self.summary(), "results": [asdict(r) for r in self.results]}


def run_probe(target, probe: Probe, scenario: Scenario) -> ProbeResult:
    user, docs = probe.materialize(scenario)
    try:
        response = target.respond(TargetRequest(scenario.system_prompt, user, docs))
    except Exception as exc:  # a crashing target must not abort the whole campaign
        return ProbeResult(probe.id, probe.category, list(probe.owasp), probe.technique, probe.benign,
                           False, {}, None, [], "", [], error=f"{type(exc).__name__}: {exc}")
    fired = {} if probe.benign else evaluate(response, scenario, probe.detectors)
    return ProbeResult(
        probe_id=probe.id,
        category=probe.category,
        owasp=list(probe.owasp),
        technique=probe.technique,
        benign=probe.benign,
        success=bool(fired),
        evidence=fired,
        intervened=response.blocked_by,
        guardrail_notes=response.guardrail_notes,
        response_excerpt=response.text[:240],
        tool_calls=[{"name": c.name, "args": c.args} for c in response.tool_calls],
    )


def run(target, probes: ProbeSet, scenario: Scenario, benign: ProbeSet | None = None) -> RunResult:
    result = RunResult(target=target.name)
    for probe in [*probes.probes, *(benign.probes if benign else [])]:
        result.results.append(run_probe(target, probe, scenario))
    return result


LAYERS = ("input_filter", "document_filter", "output_filter", "tool_policy")


def ablation(inner, probes: ProbeSet, scenario: Scenario, benign: ProbeSet | None = None) -> dict[str, RunResult]:
    """Measure each guardrail layer in isolation, plus none and all, to show
    which layer carries which attack class (and that they overlap)."""
    from .guardrails import GuardedTarget, GuardrailConfig  # local: avoid import cycle

    configs = {"none": None}
    for layer in LAYERS:
        configs[f"only {layer}"] = GuardrailConfig(**{name: name == layer for name in LAYERS})
    configs["all layers"] = GuardrailConfig()

    results = {}
    for label, config in configs.items():
        target = inner if config is None else GuardedTarget(inner, scenario, config)
        results[label] = run(target, probes, scenario, benign)
    return results
