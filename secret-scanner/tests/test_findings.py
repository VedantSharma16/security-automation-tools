from secret_scanner.findings import Finding, dedupe, highest_severity, redact, risk_score


def _finding(**overrides):
    defaults = dict(
        rule_id="aws-access-key-id",
        category="signature",
        severity="critical",
        file_path="config.py",
        line_number=1,
        redacted_value="AKIA****MNOP",
        description="AWS access key ID",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_redact_short_value_masks_all_but_first_char():
    assert redact("abcd") == "a***"


def test_redact_long_value_keeps_boundary_chars():
    result = redact("AKIAABCDEFGHIJKLMNOP")
    assert result.startswith("AKIA")
    assert result.endswith("MNOP")
    assert "*" in result
    assert len(result) == len("AKIAABCDEFGHIJKLMNOP")


def test_redact_never_contains_the_middle_of_the_secret():
    secret = "topsecretvalue1234567890"
    result = redact(secret)
    assert secret[6:-4] not in result


def test_dedupe_removes_exact_duplicates():
    findings = [_finding(), _finding(), _finding(line_number=2)]
    result = dedupe(findings)
    assert len(result) == 2


def test_risk_score_saturates_at_100():
    findings = [_finding(severity="critical") for _ in range(10)]
    assert risk_score(findings) == 100


def test_risk_score_zero_for_no_findings():
    assert risk_score([]) == 0


def test_highest_severity_picks_the_worst():
    findings = [_finding(severity="low"), _finding(severity="critical"), _finding(severity="medium")]
    assert highest_severity(findings) == "critical"


def test_highest_severity_none_for_empty_list():
    assert highest_severity([]) is None


def test_to_dict_omits_commit_info_when_absent():
    d = _finding().to_dict()
    assert "commit" not in d


def test_to_dict_includes_commit_info_when_present():
    d = _finding(
        source="git_history",
        commit_hash="abc123",
        commit_author="Jane Doe",
        commit_date="2026-01-01",
        commit_subject="add config",
    ).to_dict()
    assert d["commit"]["hash"] == "abc123"
    assert d["commit"]["author"] == "Jane Doe"
