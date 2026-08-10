from webauditor.exposure import check_exposed_paths
from webauditor.fetcher import FetchResult
from webauditor.findings import Severity


def make_result(url, status_code=404, body=""):
    return FetchResult(
        url=url, final_url=url, status_code=status_code,
        headers={}, elapsed_seconds=0.01, body_preview=body,
    )


def test_no_findings_when_all_paths_404():
    def fetch_fn(url):
        return make_result(url, status_code=404, body="")

    findings = check_exposed_paths("https://example.com", fetch_fn)
    assert findings == []


def test_exposed_git_head_flagged_critical():
    def fetch_fn(url):
        if url.endswith(".git/HEAD"):
            return make_result(url, status_code=200, body="ref: refs/heads/main")
        return make_result(url, status_code=404)

    findings = check_exposed_paths("https://example.com", fetch_fn)
    assert len(findings) == 1
    assert findings[0].id == "EXP-GIT-EXPOSED"
    assert findings[0].severity == Severity.CRITICAL


def test_exposed_dotenv_flagged_critical():
    def fetch_fn(url):
        if url.endswith("/.env"):
            return make_result(url, status_code=200, body="DB_PASSWORD=hunter2")
        return make_result(url, status_code=404)

    findings = check_exposed_paths("https://example.com", fetch_fn)
    assert any(f.id == "EXP-DOTENV-EXPOSED" for f in findings)


def test_empty_200_body_is_not_treated_as_exposed():
    def fetch_fn(url):
        return make_result(url, status_code=200, body="   ")

    findings = check_exposed_paths("https://example.com", fetch_fn)
    assert findings == []


def test_network_error_result_is_not_treated_as_exposed():
    def fetch_fn(url):
        return FetchResult(
            url=url, final_url=url, status_code=0, headers={},
            elapsed_seconds=0.0, error="connection refused",
        )

    findings = check_exposed_paths("https://example.com", fetch_fn)
    assert findings == []


def test_security_txt_present_is_informational_not_a_risk():
    def fetch_fn(url):
        if url.endswith("security.txt"):
            return make_result(url, status_code=200, body="Contact: mailto:security@example.com")
        return make_result(url, status_code=404)

    findings = check_exposed_paths("https://example.com", fetch_fn)
    assert len(findings) == 1
    assert findings[0].id == "EXP-SECURITY-TXT"
    assert findings[0].severity == Severity.INFO


def test_trailing_slash_in_base_url_is_normalized():
    seen_urls = []

    def fetch_fn(url):
        seen_urls.append(url)
        return make_result(url, status_code=404)

    check_exposed_paths("https://example.com/", fetch_fn)
    assert all("//" not in u.split("://", 1)[1] for u in seen_urls)
