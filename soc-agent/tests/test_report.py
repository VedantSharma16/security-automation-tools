from soc_agent.offline_planner import Step
from soc_agent.report import exit_code_for, render_text, to_dict
from soc_agent.tools import Verdict


def _verdict(severity="high"):
    return Verdict(
        severity=severity,
        summary="Something happened.",
        key_indicators=["1.2.3.4", "admin"],
        matched_techniques=["T1110 Brute Force"],
        recommended_actions=["Isolate the host.", "Reset credentials."],
        steps_taken=2,
    )


def _transcript():
    return [
        Step("check_ioc_reputation", {"indicator": "1.2.3.4"}, {"known_malicious": True}),
        Step("finish_investigation", {"severity": "high"}, {"severity": "high"}),
    ]


def test_render_text_includes_all_sections():
    text = render_text(_verdict(), _transcript(), mode="offline")
    assert "HIGH" in text
    assert "Something happened." in text
    assert "1.2.3.4" in text
    assert "T1110 Brute Force" in text
    assert "Isolate the host." in text
    assert "check_ioc_reputation" in text


def test_render_text_can_hide_transcript():
    text = render_text(_verdict(), _transcript(), mode="offline", show_transcript=False)
    assert "check_ioc_reputation" not in text
    assert "HIGH" in text


def test_to_dict_round_trips_key_fields():
    report = to_dict(_verdict(), _transcript(), alert_text="raw alert", mode="offline")
    assert report["mode"] == "offline"
    assert report["alert_text"] == "raw alert"
    assert report["verdict"]["severity"] == "high"
    assert len(report["transcript"]) == 2


def test_exit_code_for_threshold_boundaries():
    assert exit_code_for(_verdict("low"), min_fail_severity="high") == 0
    assert exit_code_for(_verdict("high"), min_fail_severity="high") == 1
    assert exit_code_for(_verdict("critical"), min_fail_severity="high") == 1
    assert exit_code_for(_verdict("medium"), min_fail_severity="critical") == 0
