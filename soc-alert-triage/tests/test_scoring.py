from soc_triage.models import Alert
from soc_triage.scoring import classify_severity, recommended_actions_for, score_indicators


def make_alert(process_name="notepad.exe", command_line="", description=""):
    return Alert(
        id="TEST-1",
        timestamp="2026-07-14T00:00:00Z",
        source="EDR",
        host="HOST-1",
        user="tester",
        process_name=process_name,
        command_line=command_line,
        description=description,
    )


def test_score_indicators_flags_offensive_tool():
    alert = make_alert(process_name="mimikatz.exe", command_line="mimikatz.exe sekurlsa::logonpasswords")
    indicators, score = score_indicators(alert)
    assert any("mimikatz" in i for i in indicators)
    assert score > 0


def test_score_indicators_flags_obfuscation():
    alert = make_alert(command_line="powershell.exe -nop -w hidden -enc SQBFAFgA")
    indicators, score = score_indicators(alert)
    assert any("hidden window" in i for i in indicators)
    assert any("encoded PowerShell" in i for i in indicators)
    assert score > 0


def test_score_indicators_benign_alert_has_no_hits():
    alert = make_alert(command_line="notepad.exe C:\\Users\\alice\\report.txt")
    indicators, score = score_indicators(alert)
    assert indicators == []
    assert score == 0.0


def test_classify_severity_boundaries():
    assert classify_severity(0.0) == "low"
    assert classify_severity(0.19) == "low"
    assert classify_severity(0.2) == "medium"
    assert classify_severity(0.4) == "high"
    assert classify_severity(0.75) == "critical"
    assert classify_severity(1.0) == "critical"


def test_recommended_actions_known_and_default_tactics():
    assert len(recommended_actions_for("Credential Access")) > 0
    assert recommended_actions_for("some-unknown-tactic") == recommended_actions_for("default")
