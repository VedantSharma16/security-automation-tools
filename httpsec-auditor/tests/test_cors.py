from httpsec.cors import analyze_cors

PROBE = "https://untrusted-probe.httpsec-auditor.example"


def _ids(findings):
    return {f.id for f in findings}


def test_no_cors_headers_no_findings():
    assert analyze_cors({}, probe_origin=PROBE) == []


def test_wildcard_origin_without_credentials_is_low_severity():
    findings = analyze_cors({"Access-Control-Allow-Origin": "*"}, probe_origin=PROBE)
    assert _ids(findings) == {"cors-wildcard-origin"}
    assert findings[0].severity == "low"


def test_wildcard_origin_with_credentials_is_critical():
    findings = analyze_cors(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        probe_origin=PROBE,
    )
    assert "cors-wildcard-with-credentials" in _ids(findings)
    match = next(f for f in findings if f.id == "cors-wildcard-with-credentials")
    assert match.severity == "critical"


def test_reflects_arbitrary_origin_without_credentials_is_high():
    findings = analyze_cors({"Access-Control-Allow-Origin": PROBE}, probe_origin=PROBE)
    match = next(f for f in findings if f.id == "cors-reflects-arbitrary-origin")
    assert match.severity == "high"


def test_reflects_arbitrary_origin_with_credentials_is_critical():
    findings = analyze_cors(
        {
            "Access-Control-Allow-Origin": PROBE,
            "Access-Control-Allow-Credentials": "true",
        },
        probe_origin=PROBE,
    )
    match = next(f for f in findings if f.id == "cors-reflects-arbitrary-origin")
    assert match.severity == "critical"
    assert "session cookies" in match.description


def test_trusted_explicit_origin_not_flagged_as_reflection():
    # server allows a specific known origin that happens NOT to match our probe
    findings = analyze_cors(
        {"Access-Control-Allow-Origin": "https://trusted-partner.example"},
        probe_origin=PROBE,
    )
    assert "cors-reflects-arbitrary-origin" not in _ids(findings)
    assert "cors-wildcard-origin" not in _ids(findings)


def test_wildcard_headers_with_credentials_flagged():
    findings = analyze_cors(
        {
            "Access-Control-Allow-Origin": "https://trusted.example",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "*",
        },
        probe_origin=PROBE,
    )
    assert "cors-wildcard-headers-with-credentials" in _ids(findings)


def test_case_insensitive_header_lookup():
    findings = analyze_cors({"access-control-allow-origin": "*"}, probe_origin=PROBE)
    assert "cors-wildcard-origin" in _ids(findings)
