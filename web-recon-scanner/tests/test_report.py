from webrecon.headers import HeaderFinding
from webrecon.report import build_report, render_console, risk_grade, risk_score, to_dict
from webrecon.robots import RobotsFindings
from webrecon.tls_check import TLSFinding, TLSReport


def make_tls_report(*findings):
    return TLSReport(
        subject_cn="example.com",
        issuer_cn="Some CA",
        not_before=None,
        not_after=None,
        protocol_version="TLSv1.3",
        days_until_expiry=200,
        findings=tuple(findings),
    )


def test_risk_score_ignores_info_findings():
    report = build_report(
        target="https://example.com",
        header_findings=[HeaderFinding("X-Frame-Options", "info", True, "DENY", "ok")],
        tls_report=make_tls_report(TLSFinding("info", "fine")),
    )
    assert risk_score(report) == 0
    assert risk_grade(risk_score(report)) == "A"


def test_risk_score_sums_weighted_severities():
    report = build_report(
        target="https://example.com",
        header_findings=[
            HeaderFinding("Strict-Transport-Security", "high", False, None, "missing"),
            HeaderFinding("X-Frame-Options", "medium", True, "bogus", "bad value"),
        ],
        tls_report=make_tls_report(TLSFinding("critical", "expired")),
    )
    # high(7) + medium(3) + critical(12) = 22
    assert risk_score(report) == 22
    assert risk_grade(22) == "D"


def test_risk_score_includes_sensitive_robots_paths():
    report = build_report(
        target="https://example.com",
        robots_findings=RobotsFindings(disallowed_paths=("/admin",), sitemaps=(), sensitive_paths=("/admin",)),
    )
    assert risk_score(report) == 1


def test_render_console_includes_target_and_grade():
    report = build_report(target="https://example.com", header_findings=[])
    output = render_console(report, use_color=False)
    assert "https://example.com" in output
    assert "Grade: A" in output
    assert "No issues found." in output


def test_render_console_lists_findings_and_errors():
    report = build_report(
        target="https://example.com",
        header_findings=[HeaderFinding("Strict-Transport-Security", "high", False, None, "missing HSTS")],
        errors=["robots.txt fetch failed: timeout"],
    )
    output = render_console(report, use_color=False)
    assert "missing HSTS" in output
    assert "robots.txt fetch failed" in output


def test_to_dict_includes_risk_score_and_is_json_serializable():
    import json

    report = build_report(
        target="https://example.com",
        header_findings=[HeaderFinding("Strict-Transport-Security", "high", False, None, "missing")],
    )
    data = to_dict(report)
    assert data["risk_score"] == 7
    assert data["risk_grade"] == "C"
    json.dumps(data, default=str)  # should not raise
