from pathlib import Path

import pytest

from sigma_tuner.evaluator import load_events
from sigma_tuner.tuner import tune

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def bruteforce_events():
    return load_events(EXAMPLES / "t1110_ssh_bruteforce.jsonl")


@pytest.fixture
def credential_dumping_events():
    return load_events(EXAMPLES / "t1003.001_credential_dumping.jsonl")


def test_t1110_search_is_non_monotonic_and_converges_at_v5(bruteforce_events):
    """Locks in the exact tuning trajectory on the bundled fixture.

    v2's raw burst threshold is actually *worse* on precision than v1's naive
    rule (an internal monitoring burst dominates the matched set) -- the
    filter added in v3 is what actually fixes precision, and thresholds are
    then lowered in v4/v5 to recover recall. This test protects that story.
    """
    result = tune("T1110", bruteforce_events)

    assert [s.variant_id for s in result.steps] == [
        "v1_any_failure",
        "v2_burst_threshold",
        "v3_exclude_internal",
        "v4_lower_threshold_3",
        "v5_lower_threshold_2",
    ]

    metrics_by_variant = {s.variant_id: s.metrics for s in result.steps}
    assert (metrics_by_variant["v1_any_failure"]["precision"], metrics_by_variant["v1_any_failure"]["recall"]) == (
        0.6,
        1.0,
    )
    assert metrics_by_variant["v2_burst_threshold"]["precision"] < metrics_by_variant["v1_any_failure"]["precision"]
    assert metrics_by_variant["v3_exclude_internal"]["precision"] == 1.0
    assert metrics_by_variant["v3_exclude_internal"]["recall"] < 0.8  # doesn't meet threshold yet

    assert result.converged is True
    assert result.final_step.variant_id == "v5_lower_threshold_2"
    assert result.final_metrics["precision"] == 1.0
    assert result.final_metrics["recall"] == pytest.approx(0.8333, abs=1e-3)


def test_t1003_converges_on_second_variant(credential_dumping_events):
    """The naive keyword rule (v1) both misses evasive techniques and false-positives
    on benign tools; the technique-specific rule (v2) is a clean win."""
    result = tune("T1003.001", credential_dumping_events)

    assert result.converged is True
    assert result.final_step.variant_id == "v2_known_techniques"
    assert result.final_metrics == {
        "total_events": 8,
        "tp": 3,
        "fp": 0,
        "fn": 0,
        "tn": 5,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "matched_indices": [0, 1, 2],
    }

    v1 = result.steps[0].metrics
    assert v1["precision"] < 1.0
    assert v1["recall"] < 1.0


def test_max_iterations_caps_the_search(bruteforce_events):
    result = tune("T1110", bruteforce_events, max_iterations=2)

    assert len(result.steps) == 2
    assert result.converged is False  # neither v1 nor v2 meets the default 0.8/0.8 thresholds
    # falls back to whichever of the two tried variants had the best F1
    assert result.final_step.variant_id == "v1_any_failure"


def test_thresholds_are_configurable(bruteforce_events):
    # A lax recall threshold lets the search stop as soon as precision is perfect,
    # even though recall hasn't caught up to 0.8 yet.
    result = tune("T1110", bruteforce_events, precision_threshold=1.0, recall_threshold=0.3)

    assert result.converged is True
    assert result.final_step.variant_id == "v3_exclude_internal"


def test_unknown_technique_raises(bruteforce_events):
    with pytest.raises(KeyError):
        tune("T9999", bruteforce_events)
