from attack_surface_mapper.models import Finding, OpenPort
from attack_surface_mapper import scoring


def test_compute_risk_clean_host_is_info():
    score, level = scoring.compute_risk([], [])
    assert (score, level) == (0, "info")


def test_compute_risk_routine_port_only_is_low():
    ports = [OpenPort(port=443, service="https", sensitive=False)]
    score, level = scoring.compute_risk(ports, [])
    assert level == "low"
    assert score == 2


def test_compute_risk_sensitive_port_pushes_to_high():
    ports = [OpenPort(port=3389, service="rdp", sensitive=True)]
    score, level = scoring.compute_risk(ports, [])
    assert score == 40
    assert level == "high"


def test_compute_risk_critical_finding_dominates():
    findings = [Finding(category="tls", severity="critical", title="x", detail="y")]
    score, level = scoring.compute_risk([], findings)
    assert score == 40
    assert level == "critical"


def test_compute_risk_score_caps_at_100():
    findings = [
        Finding(category="tls", severity="critical", title=str(i), detail="")
        for i in range(5)
    ]
    score, level = scoring.compute_risk([], findings)
    assert score == 100
    assert level == "critical"


def test_compute_risk_multiple_low_findings_accumulate():
    findings = [
        Finding(category="header", severity="low", title="a", detail=""),
        Finding(category="header", severity="low", title="b", detail=""),
        Finding(category="header", severity="medium", title="c", detail=""),
    ]
    score, level = scoring.compute_risk([], findings)
    assert score == 20
    assert level == "medium"
