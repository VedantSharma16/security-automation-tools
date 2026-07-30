from webrecon.models import Severity
from webrecon.paths import discover_sensitive_paths


def _fake_get(routes: dict):
    def _get(url: str, timeout: float) -> tuple[int, bytes]:
        for suffix, response in routes.items():
            if url.endswith(suffix):
                return response
        return routes.get("__default__", (404, b"not found"))

    return _get


def test_real_exposed_git_config_is_reported():
    routes = {
        "/.git/config": (200, b"[core]\n\trepositoryformatversion = 0\n"),
        "__default__": (404, b"not found"),
    }
    findings = discover_sensitive_paths(
        "http://example.test",
        _fake_get(routes),
        paths=[(".git/config", "Exposed .git/config", Severity.CRITICAL, "vcs disclosure")],
    )
    assert len(findings) == 1
    assert findings[0].id == "path-.git-config"


def test_soft_404_spa_does_not_produce_false_positive():
    # Every unknown path (including the real check) returns the same 200 SPA shell.
    spa_body = b"<html><body>App Shell</body></html>" * 5
    routes = {"__default__": (200, spa_body)}

    findings = discover_sensitive_paths(
        "http://example.test",
        _fake_get(routes),
        paths=[(".env", "Exposed .env file", Severity.CRITICAL, "secrets disclosure")],
    )
    assert findings == []


def test_distinct_body_on_soft_200_host_is_still_flagged():
    routes = {
        "__default__": (200, b"generic shell page"),
        "/.env": (200, b"DB_PASSWORD=hunter2\nAPI_KEY=abcdef012345\n"),
    }
    findings = discover_sensitive_paths(
        "http://example.test",
        _fake_get(routes),
        paths=[(".env", "Exposed .env file", Severity.CRITICAL, "secrets disclosure")],
    )
    assert len(findings) == 1


def test_404_paths_are_not_reported():
    routes = {"__default__": (404, b"not found")}
    findings = discover_sensitive_paths(
        "http://example.test",
        _fake_get(routes),
        paths=[(".env", "Exposed .env file", Severity.CRITICAL, "secrets disclosure")],
    )
    assert findings == []


def test_network_error_on_one_path_does_not_abort_the_scan():
    def flaky_get(url, timeout):
        if url.endswith("/broken"):
            raise ConnectionError("boom")
        if url.endswith("/.env"):
            return 200, b"DB_PASSWORD=hunter2"
        return 404, b"not found"

    findings = discover_sensitive_paths(
        "http://example.test",
        flaky_get,
        paths=[
            ("broken", "Broken path", Severity.LOW, "test"),
            (".env", "Exposed .env file", Severity.CRITICAL, "secrets disclosure"),
        ],
    )
    assert len(findings) == 1
    assert findings[0].id == "path-.env"
