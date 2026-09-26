import pytest

from sigma_tuner.technique_kb import get_technique, list_techniques


def test_list_techniques_includes_bundled_ids():
    techniques = list_techniques()
    assert "T1110" in techniques
    assert "T1003.001" in techniques
    assert techniques == sorted(techniques)


def test_get_technique_returns_ordered_variants():
    technique = get_technique("T1110")
    assert technique["name"] == "Brute Force"
    ids = [v["id"] for v in technique["variants"]]
    assert ids == [
        "v1_any_failure",
        "v2_burst_threshold",
        "v3_exclude_internal",
        "v4_lower_threshold_3",
        "v5_lower_threshold_2",
    ]
    for variant in technique["variants"]:
        assert "condition" in variant["detection"]


def test_get_unknown_technique_raises_with_helpful_message():
    with pytest.raises(KeyError, match="T9999"):
        get_technique("T9999")
