import pytest

from codesec.findings import Finding, Severity


def test_severity_ordering():
    assert Severity.LOW < Severity.HIGH
    assert Severity.CRITICAL > Severity.MEDIUM
    assert max(Severity.LOW, Severity.CRITICAL, Severity.MEDIUM) == Severity.CRITICAL


def test_severity_from_name_case_insensitive():
    assert Severity.from_name("high") == Severity.HIGH
    assert Severity.from_name("CRITICAL") == Severity.CRITICAL


def test_severity_from_name_rejects_unknown():
    with pytest.raises(ValueError):
        Severity.from_name("nope")


def test_finding_to_dict_uses_severity_name():
    finding = Finding(
        rule_id="r",
        title="t",
        severity=Severity.MEDIUM,
        cwe="CWE-1",
        file="f.py",
        line=3,
        snippet="s",
        description="d",
        remediation="fix",
    )
    d = finding.to_dict()
    assert d["severity"] == "MEDIUM"
    assert d["line"] == 3
    assert d["column"] == 0
