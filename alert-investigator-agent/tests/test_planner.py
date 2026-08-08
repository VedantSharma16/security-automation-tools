from investigator import planner
from investigator.state import Alert


def test_malicious_indicator_on_critical_asset_is_true_positive():
    alert = Alert(
        alert_id="ALT-001",
        description="Multiple failed login attempts from external IP against VPN gateway.",
        indicators=["185.220.101.45"],
        host="fin-db-03",
    )
    result = planner.run(alert)

    assert result.verdict == "true_positive"
    assert result.confidence == "high"
    assert result.risk_band in ("high", "critical")
    assert result.mode == "offline_planner"
    assert any(step.tool == "calculate_risk_score" for step in result.trace)


def test_clean_indicator_on_low_value_asset_is_false_positive_and_skips_history():
    alert = Alert(
        alert_id="ALT-002",
        description="Routine scheduled backup job completed successfully.",
        indicators=["9.9.9.9"],
        host="dev-sandbox-07",
    )
    result = planner.run(alert)

    assert result.verdict == "false_positive"
    assert result.risk_band == "low"

    history_steps = [s for s in result.trace if s.tool == "search_alert_history"]
    assert len(history_steps) == 1
    assert history_steps[0].output.get("skipped") is True


def test_malicious_indicator_without_corroboration_needs_escalation():
    alert = Alert(
        alert_id="ALT-003",
        description="Unusual outbound beacon traffic detected from internal host.",
        indicators=["45.155.204.12"],
        host="web-app-12",
    )
    result = planner.run(alert)

    assert result.verdict == "needs_escalation"
    assert result.confidence == "medium"
    # Malicious indicator forces a history check even though the asset criticality is only medium.
    history_steps = [s for s in result.trace if s.tool == "search_alert_history"]
    assert len(history_steps) == 1
    assert history_steps[0].output.get("skipped") is not True


def test_allowlisted_indicator_is_not_treated_as_malicious():
    alert = Alert(
        alert_id="ALT-004",
        description="Outbound DNS query to public resolver.",
        indicators=["8.8.8.8"],
        host="web-app-12",
    )
    result = planner.run(alert)

    reputation_steps = [s for s in result.trace if s.tool == "lookup_indicator_reputation"]
    assert reputation_steps[0].output["is_known_malicious"] is False
    assert result.verdict != "true_positive"


def test_multiple_indicators_each_get_a_reputation_lookup():
    alert = Alert(
        alert_id="ALT-005",
        description="Alert with multiple indicators.",
        indicators=["185.220.101.45", "8.8.8.8"],
        host="vpn-gw-01",
    )
    result = planner.run(alert)

    reputation_steps = [s for s in result.trace if s.tool == "lookup_indicator_reputation"]
    assert len(reputation_steps) == 2
    assert {s.input["indicator"] for s in reputation_steps} == {"185.220.101.45", "8.8.8.8"}


def test_unknown_host_yields_unknown_criticality_and_lower_confidence():
    alert = Alert(
        alert_id="ALT-006",
        description="Routine scheduled backup job completed successfully.",
        indicators=["9.9.9.9"],
        host="totally-unknown-host",
    )
    result = planner.run(alert)

    asset_steps = [s for s in result.trace if s.tool == "get_asset_context"]
    assert asset_steps[0].output["found"] is False
    assert result.confidence == "low"


def test_recommended_actions_include_technique_playbook_when_matched():
    alert = Alert(
        alert_id="ALT-007",
        description="Multiple failed login attempts, password spray pattern observed.",
        indicators=["203.0.113.77"],
        host="vpn-gw-01",
    )
    result = planner.run(alert)

    assert any("MFA" in action or "Lock" in action for action in result.recommended_actions)


def test_result_round_trips_through_to_dict():
    alert = Alert(alert_id="ALT-008", description="Benign event.", indicators=[], host=None)
    result = planner.run(alert)
    payload = result.to_dict()

    assert payload["alert"]["alert_id"] == "ALT-008"
    assert payload["mode"] == "offline_planner"
    assert isinstance(payload["trace"], list)
