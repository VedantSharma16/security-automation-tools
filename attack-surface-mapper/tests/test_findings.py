from asm.findings import Finding, Severity, build_summary


def test_build_summary_empty():
    summary = build_summary([])
    assert summary == {
        "total_findings": 0,
        "by_severity": {s.name: 0 for s in Severity},
        "risk_score": 0,
        "highest_severity": None,
    }


def test_info_findings_do_not_affect_risk_score():
    findings = [Finding("dns", Severity.INFO, "title", "detail") for _ in range(10)]
    summary = build_summary(findings)
    assert summary["risk_score"] == 0
    assert summary["highest_severity"] is None
    assert summary["total_findings"] == 10


def test_risk_score_uses_highest_weighted_severities():
    findings = [
        Finding("tls", Severity.CRITICAL, "expired cert", "..."),
        Finding("http_headers", Severity.LOW, "missing header", "..."),
    ]
    summary = build_summary(findings)
    assert summary["highest_severity"] == "CRITICAL"
    assert summary["risk_score"] == 55  # 50 (critical) + 5 (low)


def test_risk_score_caps_at_100():
    findings = [Finding("tls", Severity.CRITICAL, f"finding {i}", "...") for i in range(5)]
    summary = build_summary(findings)
    assert summary["risk_score"] == 100


def test_finding_to_dict():
    f = Finding("dns", Severity.MEDIUM, "No SPF record", "detail text")
    assert f.to_dict() == {
        "source": "dns",
        "severity": "MEDIUM",
        "title": "No SPF record",
        "detail": "detail text",
    }
