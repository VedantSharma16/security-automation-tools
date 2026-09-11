from webaudit import cors

ORIGIN = "https://cors-probe.invalid"


def test_no_acao_header_passes():
    results = cors.analyze_cors({}, ORIGIN)
    assert results[0].status == "pass"


def test_wildcard_without_credentials_is_informational():
    results = cors.analyze_cors({"access-control-allow-origin": "*"}, ORIGIN)
    assert results[0].status == "info"


def test_wildcard_with_credentials_fails():
    results = cors.analyze_cors(
        {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}, ORIGIN
    )
    assert results[0].status == "fail"
    assert results[0].severity == "high"


def test_reflected_origin_fails_high_without_credentials():
    results = cors.analyze_cors({"access-control-allow-origin": ORIGIN}, ORIGIN)
    assert results[0].status == "fail"
    assert results[0].severity == "high"


def test_reflected_origin_with_credentials_is_critical():
    results = cors.analyze_cors(
        {
            "access-control-allow-origin": ORIGIN,
            "access-control-allow-credentials": "true",
        },
        ORIGIN,
    )
    assert results[0].status == "fail"
    assert results[0].severity == "critical"


def test_allow_listed_origin_passes():
    results = cors.analyze_cors(
        {"access-control-allow-origin": "https://trusted-partner.example"}, ORIGIN
    )
    assert results[0].status == "pass"
