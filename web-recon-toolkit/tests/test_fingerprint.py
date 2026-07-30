from webrecon.fingerprint import fingerprint


def test_no_signals_produces_no_findings():
    assert fingerprint({}, "", []) == []


def test_server_header_detected():
    findings = fingerprint({"Server": "nginx/1.18.0"}, "", [])
    assert len(findings) == 1
    assert "nginx/1.18.0" in findings[0].evidence
    assert findings[0].severity.name == "INFO"


def test_generator_meta_tag_detected():
    body = '<html><head><meta name="generator" content="WordPress 6.2"></head></html>'
    findings = fingerprint({}, body, [])
    assert len(findings) == 1
    assert "WordPress 6.2" in findings[0].evidence


def test_cookie_name_maps_to_technology():
    findings = fingerprint({}, "", ["JSESSIONID"])
    assert len(findings) == 1
    assert "Java" in findings[0].evidence


def test_unknown_cookie_name_ignored():
    findings = fingerprint({}, "", ["some_random_cookie"])
    assert findings == []


def test_multiple_signals_combine_into_one_finding():
    findings = fingerprint(
        {"Server": "Apache", "X-Powered-By": "PHP/8.1"}, "", ["PHPSESSID"]
    )
    assert len(findings) == 1
    evidence = findings[0].evidence
    assert "Apache" in evidence and "PHP/8.1" in evidence and "PHP" in evidence
