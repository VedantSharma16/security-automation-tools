from phish_forensics.authresults import parse_authentication_results


def test_no_headers_means_not_evaluated():
    summary = parse_authentication_results([])
    assert not summary.evaluated
    assert summary.spf is None
    assert summary.failing_mechanisms() == []
    assert not summary.fully_authenticated()


def test_parses_all_three_mechanisms():
    header = "mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass header.from=example.com"
    summary = parse_authentication_results([header])
    assert summary.spf == "pass"
    assert summary.dkim == "pass"
    assert summary.dmarc == "pass"
    assert summary.fully_authenticated()
    assert summary.failing_mechanisms() == []


def test_detects_failures():
    header = "mx.example.com; spf=fail smtp.mailfrom=evil.com; dkim=none; dmarc=fail header.from=evil.com"
    summary = parse_authentication_results([header])
    assert set(summary.failing_mechanisms()) == {"spf", "dmarc"}
    assert not summary.fully_authenticated()


def test_topmost_header_wins_when_multiple_present():
    headers = [
        "mx.final-hop.com; spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass",
        "mx.earlier-hop.com; spf=fail smtp.mailfrom=example.com; dkim=fail; dmarc=fail",
    ]
    summary = parse_authentication_results(headers)
    assert summary.spf == "pass"
    assert summary.dkim == "pass"
    assert summary.dmarc == "pass"


def test_softfail_and_permerror_count_as_failing():
    header = "mx.example.com; spf=softfail smtp.mailfrom=evil.com; dkim=permerror; dmarc=pass"
    summary = parse_authentication_results([header])
    assert set(summary.failing_mechanisms()) == {"spf", "dkim"}
