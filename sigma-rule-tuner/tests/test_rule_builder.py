from sigma_tuner.rule_builder import build_rule
from sigma_tuner.technique_kb import get_technique


def test_build_rule_assembles_expected_shape():
    technique = get_technique("T1110")
    variant = technique["variants"][2]  # v3_exclude_internal, has both selection and filter blocks

    rule = build_rule(technique, "T1110", variant)

    assert rule["title"] == "Brute Force (v3_exclude_internal)"
    assert rule["id"] == "t1110-v3_exclude_internal"
    assert rule["status"] == "experimental"
    assert rule["description"] == variant["rationale"]
    assert rule["tags"] == ["attack.credential_access", "attack.t1110"]
    assert rule["logsource"] == {"product": "linux", "service": "sshd"}
    assert rule["detection"] == variant["detection"]
    assert rule["falsepositives"] == technique["falsepositives"]
    assert rule["level"] == "medium"


def test_build_rule_falls_back_to_technique_level_default():
    technique = get_technique("T1003.001")
    variant = dict(technique["variants"][0])
    variant.pop("level", None)

    rule = build_rule(technique, "T1003.001", variant)

    assert rule["level"] == technique["level_default"]


def test_build_rule_does_not_mutate_shared_kb_dicts():
    technique = get_technique("T1110")
    variant = technique["variants"][0]

    rule = build_rule(technique, "T1110", variant)
    rule["detection"]["selection"]["event_type"] = "mutated"
    rule["tags"].append("extra")

    # A second build from the same (cached) KB entry must be unaffected.
    fresh = build_rule(get_technique("T1110"), "T1110", get_technique("T1110")["variants"][0])
    assert fresh["detection"]["selection"]["event_type"] == "auth_failure"
    assert "extra" not in fresh["tags"]
