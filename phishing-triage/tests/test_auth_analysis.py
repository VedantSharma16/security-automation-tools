from __future__ import annotations

from phishing_triage.auth_analysis import analyze_authentication


def test_no_headers_present():
    result = analyze_authentication([])
    assert result.header_present is False
    assert result.spf is None
    assert result.fully_authenticated is False
    assert result.any_hard_fail is False


def test_all_pass():
    header = (
        "mx.example.com; spf=pass smtp.mailfrom=example.com; "
        "dkim=pass header.i=@example.com; dmarc=pass (p=REJECT) header.from=example.com"
    )
    result = analyze_authentication([header])
    assert result.header_present is True
    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"
    assert result.fully_authenticated is True
    assert result.any_hard_fail is False


def test_hard_fail_detected():
    header = "mx.example.com; spf=fail smtp.mailfrom=evil.tk; dkim=fail; dmarc=fail (p=REJECT)"
    result = analyze_authentication([header])
    assert result.spf == "fail"
    assert result.dmarc == "fail"
    assert result.any_hard_fail is True
    assert result.fully_authenticated is False


def test_softfail_is_not_a_hard_fail():
    header = "mx.example.com; spf=softfail; dkim=none; dmarc=none"
    result = analyze_authentication([header])
    assert result.spf == "softfail"
    assert result.any_hard_fail is False


def test_first_header_wins_when_multiple_present():
    headers = [
        "mx.recipient.example; spf=fail; dkim=fail; dmarc=fail",
        "mx.intermediate-hop.example; spf=pass; dkim=pass; dmarc=pass",
    ]
    result = analyze_authentication(headers)
    assert result.spf == "fail"
    assert result.dkim == "fail"
    assert result.dmarc == "fail"


def test_unknown_mechanism_values_are_ignored():
    header = "mx.example.com; spf=notarealresult"
    result = analyze_authentication([header])
    assert result.spf is None


def test_as_dict_roundtrip():
    header = "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
    result = analyze_authentication([header])
    d = result.as_dict()
    assert d == {
        "header_present": True,
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "fully_authenticated": True,
    }
