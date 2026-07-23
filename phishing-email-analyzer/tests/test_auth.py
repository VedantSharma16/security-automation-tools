from phishtriage.auth import parse_authentication_results


def test_missing_header_returns_absent_result():
    result = parse_authentication_results(None)
    assert not result.present
    assert result.failing_mechanisms == []
    assert not result.dmarc_fail


def test_all_pass_has_no_failing_mechanisms():
    raw = "mx.example.com; spf=pass smtp.mailfrom=acme.com; dkim=pass header.d=acme.com; dmarc=pass"
    result = parse_authentication_results(raw)
    assert result.present
    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"
    assert result.failing_mechanisms == []
    assert not result.dmarc_fail


def test_dmarc_fail_is_flagged():
    raw = "mx.example.com; spf=fail smtp.mailfrom=evil.com; dkim=fail header.d=evil.com; dmarc=fail action=reject"
    result = parse_authentication_results(raw)
    assert result.dmarc_fail
    assert set(result.failing_mechanisms) == {"spf", "dkim", "dmarc"}


def test_softfail_counts_as_failing():
    raw = "mx.example.com; spf=softfail smtp.mailfrom=evil.com; dkim=none; dmarc=none"
    result = parse_authentication_results(raw)
    assert result.failing_mechanisms == ["spf"]
    assert not result.dmarc_fail
