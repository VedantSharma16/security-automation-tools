from webauditor.auditor import run_audit
from webauditor.fetch import FetchResult


class StubFetcher:
    """Serves a canned response for URLs matching a suffix; 404s otherwise."""

    def __init__(self, routes: dict[str, FetchResult]):
        self._routes = routes

    def get(self, url, extra_headers=None):
        for suffix, result in self._routes.items():
            if url.endswith(suffix):
                return result
        return FetchResult(url=url, status_code=404, body="")


def _base_response(headers=None) -> FetchResult:
    return FetchResult(
        url="https://example.com/",
        status_code=200,
        headers=headers
        or {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        },
        body="<html></html>",
    )


def test_unreachable_target_returns_single_informational_finding():
    fetcher = StubFetcher({"": FetchResult(url="x", status_code=None, error="refused")})
    findings = run_audit(
        "https://example.com",
        fetcher=fetcher,
        skip_tls=True,
        skip_cors=True,
        skip_disclosure=True,
    )
    assert len(findings) == 1
    assert findings[0].id == "target-unreachable"


def test_hardened_target_with_all_checks_skipped_has_no_findings():
    fetcher = StubFetcher({"": _base_response()})
    findings = run_audit(
        "https://example.com",
        fetcher=fetcher,
        skip_tls=True,
        skip_cors=True,
        skip_disclosure=True,
    )
    assert findings == []


def test_skip_flags_are_respected():
    fetcher = StubFetcher(
        {
            "": _base_response(headers={"Access-Control-Allow-Origin": "*"}),
        }
    )
    findings = run_audit(
        "https://example.com",
        fetcher=fetcher,
        skip_tls=True,
        skip_cors=True,
        skip_disclosure=True,
    )
    assert not any(f.id.startswith("cors-") for f in findings)


def test_http_target_skips_tls_automatically():
    fetcher = StubFetcher({"": _base_response(headers={})})
    calls = []

    def tracking_tls_info(hostname, port):
        calls.append((hostname, port))
        raise AssertionError("should not be called for http:// targets")

    findings = run_audit(
        "http://example.com",
        fetcher=fetcher,
        tls_info_fn=tracking_tls_info,
        skip_cors=True,
        skip_disclosure=True,
    )
    assert calls == []
    assert not any(f.id.startswith("tls-") for f in findings)
