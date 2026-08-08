from investigator import tools


def test_lookup_indicator_reputation_known_malicious():
    result = tools.lookup_indicator_reputation("185.220.101.45")
    assert result["found"] is True
    assert result["is_known_malicious"] is True
    assert result["confidence"] == "high"


def test_lookup_indicator_reputation_is_case_and_space_insensitive():
    result = tools.lookup_indicator_reputation("  UPDATE-SERVICE-CDN.COM  ")
    assert result["is_known_malicious"] is True


def test_lookup_indicator_reputation_allowlisted_entry_not_malicious():
    result = tools.lookup_indicator_reputation("8.8.8.8")
    assert result["found"] is True
    assert result["is_known_malicious"] is False


def test_lookup_indicator_reputation_unknown():
    result = tools.lookup_indicator_reputation("1.2.3.4")
    assert result["found"] is False
    assert result["is_known_malicious"] is False


def test_get_asset_context_found_by_host():
    result = tools.get_asset_context("fin-db-03")
    assert result["found"] is True
    assert result["criticality"] == "critical"


def test_get_asset_context_found_by_ip():
    result = tools.get_asset_context("10.10.0.5")
    assert result["found"] is True
    assert result["criticality"] == "high"


def test_get_asset_context_unknown_host():
    result = tools.get_asset_context("does-not-exist")
    assert result["found"] is False
    assert result["criticality"] == "unknown"


def test_search_alert_history_recurring_true_positive():
    result = tools.search_alert_history("185.220.101.45")
    assert result["prior_alert_count"] == 2
    assert result["prior_true_positive_count"] == 2
    assert result["prior_false_positive_count"] == 0


def test_search_alert_history_benign_only():
    result = tools.search_alert_history("8.8.8.8")
    assert result["prior_alert_count"] == 1
    assert result["prior_true_positive_count"] == 0
    assert result["prior_false_positive_count"] == 1


def test_search_alert_history_no_prior_activity():
    result = tools.search_alert_history("9.9.9.9")
    assert result["prior_alert_count"] == 0


def test_map_mitre_technique_matches_brute_force():
    result = tools.map_mitre_technique("Multiple failed login attempts detected, likely password spray.")
    assert result["matched"] is True
    assert result["techniques"][0]["id"] == "T1110"
    assert "recommended_actions" in result["techniques"][0]


def test_map_mitre_technique_no_match():
    result = tools.map_mitre_technique("Routine scheduled backup job completed successfully.")
    assert result["matched"] is False
    assert result["techniques"] == []


def test_calculate_risk_score_all_signals_high():
    risk = tools.calculate_risk_score(
        {
            "any_known_malicious": True,
            "max_confidence": "high",
            "asset_criticality": "critical",
            "recurring_true_positive": True,
            "technique_matched": True,
        }
    )
    assert risk["score"] == 100
    assert risk["band"] == "critical"
    assert len(risk["reasons"]) == 5


def test_calculate_risk_score_no_signals_is_low():
    risk = tools.calculate_risk_score({})
    assert risk["score"] == 0
    assert risk["band"] == "low"
    assert risk["reasons"] == []


def test_calculate_risk_score_benign_history_reduces_score():
    with_history = tools.calculate_risk_score({"asset_criticality": "critical", "seen_before_as_benign_only": True})
    without_history = tools.calculate_risk_score({"asset_criticality": "critical"})
    assert with_history["score"] < without_history["score"]


def test_calculate_risk_score_never_goes_negative():
    risk = tools.calculate_risk_score({"seen_before_as_benign_only": True})
    assert risk["score"] == 0


def test_tool_registry_contains_all_five_tools():
    expected = {
        "lookup_indicator_reputation",
        "get_asset_context",
        "search_alert_history",
        "map_mitre_technique",
        "calculate_risk_score",
    }
    assert set(tools.TOOL_REGISTRY.keys()) == expected


def test_call_tool_dispatches_by_name():
    result = tools.call_tool("lookup_indicator_reputation", {"indicator": "8.8.8.8"})
    assert result["found"] is True


def test_call_tool_unknown_name_raises():
    import pytest

    with pytest.raises(ValueError):
        tools.call_tool("not_a_real_tool", {})


def test_anthropic_tool_schemas_shape():
    schemas = tools.anthropic_tool_schemas()
    assert len(schemas) == 5
    for schema in schemas:
        assert set(schema.keys()) == {"name", "description", "input_schema"}
        assert schema["input_schema"]["type"] == "object"
