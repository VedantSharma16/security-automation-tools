from webrecon.fetcher import FetchResult
from webrecon.paths import PathRule, _looks_like_baseline, load_path_rules, probe_sensitive_paths


class FakeFetcher:
    """Minimal stand-in for Fetcher: returns canned results by path, no network."""

    def __init__(self, routes: dict[str, FetchResult], baseline: FetchResult):
        self.routes = routes
        self._baseline = baseline

    def get_path(self, base_url, path):
        key = path.lstrip("/")
        return self.routes.get(key, self._baseline)

    def baseline_404(self, base_url):
        return self._baseline


def _result(status, body=""):
    return FetchResult(url="http://x", ok=True, status_code=status, headers={}, body=body)


def test_load_path_rules_parses_bundled_file():
    rules = load_path_rules()
    assert any(r.path == ".git/config" and r.severity == "critical" for r in rules)
    assert all(r.severity in {"info", "low", "medium", "high", "critical"} for r in rules)


def test_looks_like_baseline_same_status_similar_length():
    baseline = _result(404, "x" * 100)
    candidate = _result(404, "x" * 105)
    assert _looks_like_baseline(candidate, baseline)


def test_looks_like_baseline_different_status_is_not_baseline():
    baseline = _result(404, "x" * 100)
    candidate = _result(200, "x" * 100)
    assert not _looks_like_baseline(candidate, baseline)


def test_looks_like_baseline_very_different_length_is_not_baseline():
    baseline = _result(200, "x" * 50)
    candidate = _result(200, "x" * 5000)
    assert not _looks_like_baseline(candidate, baseline)


def test_probe_flags_real_exposure_but_not_soft_404():
    baseline = _result(404, "Not Found")
    rules = [
        PathRule(severity="critical", path=".git/config", title="Exposed .git/config"),
        PathRule(severity="low", path="admin", title="Admin panel reachable"),
    ]
    routes = {
        ".git/config": _result(200, "[core]\n\trepositoryformatversion = 0\n"),
        "admin": baseline,  # this host 404s admin too -- should NOT be flagged
        ".well-known/security.txt": baseline,
    }
    fetcher = FakeFetcher(routes, baseline)

    findings = probe_sensitive_paths(fetcher, "http://example.com", rules)
    ids = {f.id for f in findings}

    assert "exposed-path-.git-config" in ids
    assert "exposed-path-admin" not in ids
    assert "missing-security-txt" in ids


def test_probe_ignores_error_responses():
    baseline = _result(404, "Not Found")
    rules = [PathRule(severity="high", path="secret.txt", title="Exposed secret")]
    routes = {"secret.txt": FetchResult(url="http://x", ok=False, error="connection reset")}
    fetcher = FakeFetcher(routes, baseline)

    findings = probe_sensitive_paths(fetcher, "http://example.com", rules)
    assert findings == [] or all(f.id != "exposed-path-secret.txt" for f in findings)
