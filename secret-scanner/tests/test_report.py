import json

from secretscanner import report as report_mod
from secretscanner.rules import load_default_rules
from secretscanner.scanner import scan_path
from sample_secrets import AWS_ACCESS_KEY_ID, GENERIC_SECRET_VALUE, PRIVATE_KEY_HEADER


def _findings(tmp_path):
    (tmp_path / "config.py").write_text(
        f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n'
        f'{PRIVATE_KEY_HEADER}\n'
    )
    return scan_path(tmp_path, load_default_rules())


def test_build_report_counts_and_sorts_by_severity(tmp_path):
    findings, files_scanned = _findings(tmp_path)
    report = report_mod.build_report(findings, str(tmp_path), files_scanned)

    assert report["finding_count"] == 2
    assert report["files_scanned"] == 1
    assert report["highest_severity"] == "critical"
    severities = [f["severity"] for f in report["findings"]]
    assert severities == sorted(severities, key=lambda s: report_mod.SEVERITY_RANK[s], reverse=True)


def test_build_report_redacts_secrets(tmp_path):
    findings, files_scanned = _findings(tmp_path)
    report = report_mod.build_report(findings, str(tmp_path), files_scanned)

    aws_finding = next(f for f in report["findings"] if f["rule_id"] == "aws-access-key-id")
    assert aws_finding["secret"] != AWS_ACCESS_KEY_ID
    assert "*" in aws_finding["secret"]


def test_filter_by_min_severity_drops_lower_severity_findings(tmp_path):
    (tmp_path / "config.py").write_text(
        f'password = "{GENERIC_SECRET_VALUE}"\n'
        f'AWS_KEY = "{AWS_ACCESS_KEY_ID}"\n'
    )
    findings, files_scanned = scan_path(tmp_path, load_default_rules())
    report = report_mod.build_report(findings, str(tmp_path), files_scanned)
    assert report["finding_count"] == 2

    filtered = report_mod.filter_by_min_severity(report, "critical")
    assert filtered["finding_count"] == 1
    assert filtered["findings"][0]["rule_id"] == "aws-access-key-id"


def test_write_json_produces_valid_json(tmp_path):
    findings, files_scanned = _findings(tmp_path)
    report = report_mod.build_report(findings, str(tmp_path), files_scanned)
    out = tmp_path / "report.json"

    report_mod.write_json(report, out)

    loaded = json.loads(out.read_text())
    assert loaded["finding_count"] == 2


def test_build_sarif_has_one_result_per_finding(tmp_path):
    findings, files_scanned = _findings(tmp_path)
    report = report_mod.build_report(findings, str(tmp_path), files_scanned)

    sarif = report_mod.build_sarif(report)

    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == report["finding_count"]
    assert all("ruleId" in r and "level" in r for r in results)


def test_render_console_reports_no_secrets_found_for_empty_report():
    report = report_mod.build_report([], "/some/path", 3)
    output = report_mod.render_console(report, use_color=False)
    assert "No secrets found" in output


def test_render_console_shows_finding_details(tmp_path):
    findings, files_scanned = _findings(tmp_path)
    report = report_mod.build_report(findings, str(tmp_path), files_scanned)
    output = report_mod.render_console(report, use_color=False)

    assert "aws-access-key-id" in output
    assert "config.py:1" in output
