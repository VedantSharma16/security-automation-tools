from webauditor.cors import PROBE_ORIGIN, check_cors
from webauditor.fetch import FetchResult


class FakeFetcher:
    def __init__(self, headers: dict[str, str]):
        self._headers = headers

    def get(self, url, extra_headers=None):
        return FetchResult(url=url, status_code=200, headers=self._headers, body="")


def test_reflected_origin_with_credentials_is_critical():
    fetcher = FakeFetcher(
        {
            "Access-Control-Allow-Origin": PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }
    )
    findings = check_cors(fetcher, "https://example.com/api")
    assert len(findings) == 1
    assert findings[0].id == "cors-reflected-origin-with-credentials"
    assert findings[0].severity.name == "CRITICAL"


def test_reflected_origin_without_credentials_is_medium():
    fetcher = FakeFetcher({"Access-Control-Allow-Origin": PROBE_ORIGIN})
    findings = check_cors(fetcher, "https://example.com/api")
    assert len(findings) == 1
    assert findings[0].id == "cors-reflected-origin"
    assert findings[0].severity.name == "MEDIUM"


def test_wildcard_without_credentials_is_informational():
    fetcher = FakeFetcher({"Access-Control-Allow-Origin": "*"})
    findings = check_cors(fetcher, "https://example.com/api")
    assert len(findings) == 1
    assert findings[0].id == "cors-wildcard-origin"
    assert findings[0].severity.name == "INFO"


def test_wildcard_with_credentials_flagged_high():
    fetcher = FakeFetcher(
        {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    )
    findings = check_cors(fetcher, "https://example.com/api")
    assert len(findings) == 1
    assert findings[0].id == "cors-wildcard-with-credentials"
    assert findings[0].severity.name == "HIGH"


def test_fixed_allowlisted_origin_not_flagged():
    fetcher = FakeFetcher({"Access-Control-Allow-Origin": "https://trusted-partner.example"})
    findings = check_cors(fetcher, "https://example.com/api")
    assert findings == []


def test_no_cors_headers_at_all_not_flagged():
    fetcher = FakeFetcher({})
    findings = check_cors(fetcher, "https://example.com/api")
    assert findings == []


def test_unreachable_target_not_flagged():
    class UnreachableFetcher:
        def get(self, url, extra_headers=None):
            return FetchResult(url=url, status_code=None, error="connection refused")

    findings = check_cors(UnreachableFetcher(), "https://example.com/api")
    assert findings == []
