from soc_triage.models import Alert
from soc_triage.retriever import TechniqueRetriever
from soc_triage.triage import TriageEngine


def make_alert(**overrides):
    base = dict(
        id="TEST-ALERT",
        timestamp="2026-07-14T00:00:00Z",
        source="EDR",
        host="HOST-1",
        user="tester",
        process_name="notepad.exe",
        command_line="",
        description="",
    )
    base.update(overrides)
    return Alert(**base)


def test_benign_alert_is_low_severity(techniques):
    engine = TriageEngine(TechniqueRetriever(techniques))
    alert = make_alert(
        process_name="notepad.exe",
        command_line="notepad.exe C:\\Users\\alice\\report.txt",
        description="User opened a local text file.",
    )
    result = engine.triage(alert)
    assert result.severity == "low"
    assert result.matched_indicators == []
    assert result.alert_id == "TEST-ALERT"


def test_credential_dumping_alert_is_critical(techniques):
    engine = TriageEngine(TechniqueRetriever(techniques))
    alert = make_alert(
        process_name="mimikatz.exe",
        command_line='mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"',
        description="Unsigned binary executed on a domain controller.",
    )
    result = engine.triage(alert)
    assert result.severity in {"high", "critical"}
    assert any(m.technique_id == "T1003" for m in result.matched_techniques)
    assert len(result.matched_indicators) > 0
    assert len(result.recommended_actions) > 0


def test_obfuscated_powershell_alert_is_elevated(techniques):
    engine = TriageEngine(TechniqueRetriever(techniques))
    alert = make_alert(
        process_name="powershell.exe",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
        description="Encoded PowerShell shortly after a phishing email.",
    )
    result = engine.triage(alert)
    assert result.severity in {"medium", "high", "critical"}
    assert result.risk_score > 0


def test_rationale_mentions_alert_id_and_host(techniques):
    engine = TriageEngine(TechniqueRetriever(techniques))
    alert = make_alert(host="SRV-DC01")
    result = engine.triage(alert)
    assert "TEST-ALERT" in result.rationale
    assert "SRV-DC01" in result.rationale


def test_results_are_json_serializable_via_asdict(techniques):
    from dataclasses import asdict
    import json

    engine = TriageEngine(TechniqueRetriever(techniques))
    result = engine.triage(make_alert())
    json.dumps(asdict(result))  # should not raise
