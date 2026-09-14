from http_audit.cors import check_cors
from http_audit.fetcher import HttpResponse


def _response(headers: dict[str, str]) -> HttpResponse:
    return HttpResponse(url="https://example.com/", status=200, headers={k.lower(): v for k, v in headers.items()})


def test_no_cors_headers_is_informational():
    findings = check_cors(_response({}))
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_wildcard_with_credentials_is_critical():
    findings = check_cors(
        _response({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    )
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_wildcard_without_credentials_is_low():
    findings = check_cors(_response({"Access-Control-Allow-Origin": "*"}))
    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_scoped_origin_with_credentials_is_informational():
    findings = check_cors(
        _response(
            {
                "Access-Control-Allow-Origin": "https://trusted.example.com",
                "Access-Control-Allow-Credentials": "true",
            }
        )
    )
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_scoped_origin_without_credentials_passes():
    findings = check_cors(_response({"Access-Control-Allow-Origin": "https://trusted.example.com"}))
    assert len(findings) == 1
    assert findings[0].severity == "pass"
