from webscan.checks.cors import check_cors
from webscan.models import ScanTarget

TEST_ORIGIN = "https://cors-probe.invalid.example"


def _target(cors_headers: dict | None) -> ScanTarget:
    return ScanTarget(
        url="https://example.com/api",
        final_url="https://example.com/api",
        status_code=200,
        cors_test_headers=cors_headers,
        cors_test_origin=TEST_ORIGIN if cors_headers is not None else None,
    )


def test_no_cors_headers_no_findings():
    assert check_cors(_target(None)) == []
    assert check_cors(_target({})) == []


def test_reflected_origin_with_credentials_is_critical():
    findings = check_cors(
        _target({"Access-Control-Allow-Origin": TEST_ORIGIN, "Access-Control-Allow-Credentials": "true"})
    )
    assert len(findings) == 1
    assert findings[0].id == "cors-reflected-origin-with-credentials"
    assert findings[0].severity == "critical"


def test_reflected_origin_without_credentials_is_medium():
    findings = check_cors(_target({"Access-Control-Allow-Origin": TEST_ORIGIN}))
    assert len(findings) == 1
    assert findings[0].id == "cors-reflected-origin"
    assert findings[0].severity == "medium"


def test_wildcard_with_credentials_is_high():
    findings = check_cors(
        _target({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    )
    assert findings[0].id == "cors-wildcard-with-credentials"
    assert findings[0].severity == "high"


def test_wildcard_without_credentials_is_info():
    findings = check_cors(_target({"Access-Control-Allow-Origin": "*"}))
    assert findings[0].id == "cors-wildcard-origin"
    assert findings[0].severity == "info"


def test_explicit_known_origin_not_flagged():
    findings = check_cors(_target({"Access-Control-Allow-Origin": "https://trusted-partner.example"}))
    assert findings == []
