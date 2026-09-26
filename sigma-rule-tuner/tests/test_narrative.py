import pytest

from sigma_tuner.evaluator import load_events
from sigma_tuner.narrative import TemplateNarrator, get_narrator
from sigma_tuner.technique_kb import get_technique
from sigma_tuner.tuner import tune

from pathlib import Path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def result():
    events = load_events(EXAMPLES / "t1110_ssh_bruteforce.jsonl")
    return tune("T1110", events)


def test_template_narrator_mentions_selected_variant_and_metrics(result):
    technique = get_technique("T1110")
    text = TemplateNarrator().narrate(result, technique)

    assert "v5_lower_threshold_2" in text
    assert "precision 1.0" in text
    assert "-> selected v5_lower_threshold_2" in text
    assert "Users who repeatedly mistype their password" in text


def test_template_narrator_flags_non_convergence():
    events = load_events(EXAMPLES / "t1110_ssh_bruteforce.jsonl")
    result = tune("T1110", events, max_iterations=1)  # v1 alone never meets thresholds
    technique = get_technique("T1110")

    text = TemplateNarrator().narrate(result, technique)

    assert "No variant met both thresholds" in text
    assert "gathering more labeled telemetry" in text


def test_get_narrator_without_llm_flag_is_always_template():
    assert isinstance(get_narrator(False), TemplateNarrator)


def test_get_narrator_falls_back_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(get_narrator(True), TemplateNarrator)
