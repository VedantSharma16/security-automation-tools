import json

from secret_fixtures import fake_aws_access_key_id
from secret_scanner.report import format_json, format_sarif, format_text, summarize
from secret_scanner.scanner import Finding


def _finding(rule_id="aws-access-key-id", severity="critical", secret=None):
    secret = secret if secret is not None else fake_aws_access_key_id()
    return Finding(
        rule_id=rule_id,
        description="AWS Access Key ID",
        severity=severity,
        file_path="app.py",
        line_number=7,
        secret=secret,
        line_text=f'key = "{secret}"',
    )


def test_summarize_counts_by_severity():
    findings = [_finding(severity="critical"), _finding(severity="critical"), _finding(severity="medium")]
    summary = summarize(findings)
    assert summary["critical"] == 2
    assert summary["medium"] == 1
    assert summary["high"] == 0


def test_format_text_reports_no_secrets_found_for_empty_list():
    assert format_text([]) == "No secrets found.\n"


def test_format_text_includes_rule_id_and_location_and_never_the_raw_secret():
    finding = _finding()
    text = format_text([finding])
    assert "aws-access-key-id" in text
    assert "app.py:7" in text
    assert finding.secret not in text
    assert finding.fingerprint in text


def test_format_json_is_valid_and_redacts_secret():
    finding = _finding()
    payload = json.loads(format_json([finding]))
    assert payload["summary"]["critical"] == 1
    assert len(payload["findings"]) == 1
    entry = payload["findings"][0]
    assert entry["rule_id"] == "aws-access-key-id"
    assert entry["secret"] != finding.secret
    assert finding.secret not in json.dumps(payload)


def test_format_sarif_has_valid_top_level_structure():
    finding = _finding()
    sarif = json.loads(format_sarif([finding]))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "secret-scanner"
    assert run["tool"]["driver"]["rules"][0]["id"] == "aws-access-key-id"
    result = run["results"][0]
    assert result["ruleId"] == "aws-access-key-id"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    assert finding.secret not in json.dumps(sarif)


def test_format_sarif_maps_severity_to_sarif_level():
    critical = json.loads(format_sarif([_finding(severity="critical")]))
    medium = json.loads(format_sarif([_finding(rule_id="generic-high-entropy-assignment", severity="medium")]))
    assert critical["runs"][0]["results"][0]["level"] == "error"
    assert medium["runs"][0]["results"][0]["level"] == "warning"
