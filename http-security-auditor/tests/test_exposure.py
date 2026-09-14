from http_audit.exposure import check_exposure
from http_audit.fetcher import HttpResponse


def test_no_exposed_paths_found():
    def transport(url: str) -> HttpResponse:
        return HttpResponse(url=url, status=404)

    findings = check_exposure("https://example.com/", transport)
    assert findings == []


def test_exposed_git_directory_flagged_critical():
    def transport(url: str) -> HttpResponse:
        status = 200 if url.endswith("/.git/HEAD") else 404
        return HttpResponse(url=url, status=status)

    findings = check_exposure("https://example.com/", transport)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].name == "/.git/HEAD"


def test_security_txt_present_is_informational_not_critical():
    def transport(url: str) -> HttpResponse:
        status = 200 if url.endswith("/.well-known/security.txt") else 404
        return HttpResponse(url=url, status=status)

    findings = check_exposure("https://example.com/", transport)
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_only_requests_same_host():
    requested_hosts = set()

    def transport(url: str) -> HttpResponse:
        from urllib.parse import urlsplit

        requested_hosts.add(urlsplit(url).netloc)
        return HttpResponse(url=url, status=404)

    check_exposure("https://example.com/some/page", transport)
    assert requested_hosts == {"example.com"}


def test_transport_failure_is_skipped_not_raised():
    def transport(url: str) -> HttpResponse:
        raise ConnectionError("simulated network failure")

    findings = check_exposure("https://example.com/", transport)
    assert findings == []
