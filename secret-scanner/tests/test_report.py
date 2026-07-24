from secretscan.models import Finding, ScanResult
from secretscan.report import severity_breakdown, to_dict, to_json, to_table

CRITICAL = Finding(
    rule_id="private-key-block",
    description="Private Key Block (PEM)",
    severity="CRITICAL",
    file="id_rsa",
    line=1,
    redacted="-----…----",
    fingerprint="fp-critical",
)
HIGH_BASELINED = Finding(
    rule_id="aws-access-key-id",
    description="AWS Access Key ID",
    severity="HIGH",
    file="config.py",
    line=5,
    redacted="AKIA…MPLE",
    fingerprint="fp-baselined",
)


def _result():
    return ScanResult(findings=[CRITICAL, HIGH_BASELINED], baselined_fingerprints={"fp-baselined"})


def test_new_and_baselined_partition_correctly():
    result = _result()
    assert result.new_findings == [CRITICAL]
    assert result.baselined_findings == [HIGH_BASELINED]


def test_severity_breakdown_counts_by_severity():
    breakdown = severity_breakdown([CRITICAL, HIGH_BASELINED])
    assert breakdown == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}


def test_to_dict_excludes_baselined_from_top_level_findings():
    data = to_dict(_result())
    assert data["summary"]["new_findings"] == 1
    assert data["summary"]["baselined_findings"] == 1
    assert [f["fingerprint"] for f in data["findings"]] == ["fp-critical"]
    assert [f["fingerprint"] for f in data["baselined"]] == ["fp-baselined"]


def test_to_json_is_valid_json_with_expected_shape():
    import json as jsonlib

    parsed = jsonlib.loads(to_json(_result()))
    assert parsed["summary"]["total_findings"] == 2


def test_to_table_lists_only_new_findings_by_default():
    table = to_table(_result())
    assert "private-key-block" in table
    assert "aws-access-key-id" not in table
    assert "1 baselined, suppressed" in table


def test_to_table_can_include_baselined_findings():
    table = to_table(_result(), show_baselined=True)
    assert "aws-access-key-id" in table
    assert "baselined" in table


def test_to_table_reports_clean_scan():
    clean = ScanResult(findings=[], baselined_fingerprints=set())
    assert to_table(clean) == "No secrets found."
