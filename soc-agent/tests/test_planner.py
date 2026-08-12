from soc_agent import planner
from soc_agent.models import Alert


def _alert(**overrides) -> Alert:
    defaults = dict(
        alert_id="ALERT-TEST-1",
        title="Repeated outbound beacon-like TLS connections",
        description=(
            "WKS-DEV-14 (10.20.4.17) beaconed repeatedly to "
            "update-service-cdn.net (185.220.101.1)."
        ),
        source_ip="10.20.4.17",
        destination="update-service-cdn.net",
        user="j.morales",
        hostname="WKS-DEV-14",
        raw_indicators=["update-service-cdn.net", "185.220.101.1"],
    )
    defaults.update(overrides)
    return Alert.from_dict(defaults)


def test_planner_flags_known_malicious_beacon_as_malicious():
    result = planner.run(_alert())
    assert result.mode == "offline"
    assert result.verdict.verdict == "malicious"
    assert result.verdict.confidence > 0.7
    tool_names = {step.tool for step in result.trace}
    assert "ioc_lookup" in tool_names
    assert "dns_lookup" in tool_names
    assert "mitre_lookup" in tool_names


def test_planner_trace_steps_are_sequentially_numbered():
    result = planner.run(_alert())
    step_numbers = [step.step for step in result.trace]
    assert step_numbers == list(range(1, len(result.trace) + 1))


def test_planner_marks_benign_alert_as_benign():
    alert = Alert.from_dict(
        {
            "alert_id": "ALERT-TEST-2",
            "title": "Routine internal file share access",
            "description": "Access to corp-fileshare.internal from an internal host.",
            "source_ip": "10.20.0.44",
            "destination": "corp-fileshare.internal",
            "hostname": "WKS-DEV-14",
            "raw_indicators": ["corp-fileshare.internal"],
        }
    )
    result = planner.run(alert)
    assert result.verdict.verdict == "benign"


def test_planner_respects_max_steps_budget():
    result = planner.run(_alert(), max_steps=2)
    assert len(result.trace) <= 2


def test_planner_handles_alert_with_no_indicators():
    alert = Alert.from_dict(
        {
            "alert_id": "ALERT-TEST-3",
            "title": "Generic alert with no network indicators",
            "description": "A vague alert describing nothing indicator-like.",
        }
    )
    result = planner.run(alert)
    assert result.verdict.verdict in ("benign", "suspicious")
