from __future__ import annotations

from conftest import make_result

from asmapper.exposure_checks import check_exposure_paths, load_exposure_paths
from asmapper.models import Severity

PATHS = [
    {
        "path": "/.env",
        "title": "Exposed .env file",
        "severity": "critical",
        "detail": "Leaks secrets.",
        "recommendation": "Remove it.",
    },
    {
        "path": "/admin",
        "title": "Admin panel",
        "severity": "info",
        "detail": "Admin panel reachable.",
    },
]


def test_flags_200_response_with_body(fake_fetcher):
    fake_fetcher.register("https://example.com/.env", make_result("https://example.com/.env", status=200, body="DB_PASS=hunter2"))
    findings = check_exposure_paths("https://example.com", fetch_fn=fake_fetcher, paths=PATHS)
    hits = [f for f in findings if f.id == "exposure-.env"]
    assert len(hits) == 1
    assert hits[0].severity == Severity.CRITICAL


def test_ignores_404(fake_fetcher):
    # fake_fetcher defaults unregistered URLs to 404
    findings = check_exposure_paths("https://example.com", fetch_fn=fake_fetcher, paths=PATHS)
    assert findings == []


def test_ignores_200_with_empty_body(fake_fetcher):
    fake_fetcher.register("https://example.com/.env", make_result("https://example.com/.env", status=200, body=""))
    findings = check_exposure_paths("https://example.com", fetch_fn=fake_fetcher, paths=PATHS)
    assert findings == []


def test_403_reported_as_access_controlled_info_finding(fake_fetcher):
    fake_fetcher.register("https://example.com/admin", make_result("https://example.com/admin", status=403, body="Forbidden"))
    findings = check_exposure_paths("https://example.com", fetch_fn=fake_fetcher, paths=PATHS)
    hit = next(f for f in findings if f.id == "exposure-admin-protected")
    assert hit.severity == Severity.INFO


def test_unreachable_target_is_skipped_not_flagged(fake_fetcher):
    from asmapper.fetcher import FetchResult

    fake_fetcher.register("https://example.com/.env", FetchResult(url="https://example.com/.env", status=None, error="timeout"))
    findings = check_exposure_paths("https://example.com", fetch_fn=fake_fetcher, paths=PATHS)
    assert findings == []


def test_default_exposure_paths_file_loads_and_is_well_formed():
    entries = load_exposure_paths()
    assert len(entries) >= 10
    for entry in entries:
        assert entry["path"].startswith("/")
        assert entry["severity"] in {"info", "low", "medium", "high", "critical"}
