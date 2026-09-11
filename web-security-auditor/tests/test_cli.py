"""CLI tests. No real network calls: fetcher functions are monkeypatched."""

from datetime import datetime, timedelta, timezone

import webaudit.cli as cli
from webaudit.fetcher import FetchResult, TLSInfo


def _fetch_result(headers, raw_header_items=None, status=200, final_url="https://example.com/"):
    return FetchResult(
        url=final_url,
        final_url=final_url,
        status=status,
        headers=headers,
        raw_header_items=raw_header_items if raw_header_items is not None else list(headers.items()),
        body=b"",
    )


GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
}


def _patch_clean_target(monkeypatch, headers=GOOD_HEADERS):
    monkeypatch.setattr(cli, "fetch", lambda url, timeout=10.0, **kw: _fetch_result(headers))
    monkeypatch.setattr(
        cli, "get_tls_info",
        lambda host, port, timeout=10.0: TLSInfo(
            protocol="TLSv1.3",
            not_before=datetime.now(timezone.utc) - timedelta(days=30),
            not_after=datetime.now(timezone.utc) + timedelta(days=200),
        ),
    )
    monkeypatch.setattr(cli, "probe_cors", lambda url, origin, timeout=10.0: _fetch_result({}))
    monkeypatch.setattr(cli, "probe_path", lambda url, path, timeout=10.0: _fetch_result({}, status=404))


def test_run_audit_clean_target_scores_high(monkeypatch):
    _patch_clean_target(monkeypatch)
    report = cli.run_audit("https://example.com")
    assert report["score"] >= 90
    assert report["summary"]["fail"] == 0


def test_run_audit_flags_missing_headers(monkeypatch):
    monkeypatch.setattr(cli, "fetch", lambda url, timeout=10.0, **kw: _fetch_result({}))
    monkeypatch.setattr(
        cli, "get_tls_info",
        lambda host, port, timeout=10.0: TLSInfo(protocol="TLSv1.3", not_before=None, not_after=None),
    )
    monkeypatch.setattr(cli, "probe_cors", lambda url, origin, timeout=10.0: _fetch_result({}))
    monkeypatch.setattr(cli, "probe_path", lambda url, path, timeout=10.0: _fetch_result({}, status=404))

    report = cli.run_audit("https://example.com")
    assert report["summary"]["fail"] > 0


def test_run_audit_no_active_probes_skips_cors_and_disclosure(monkeypatch):
    _patch_clean_target(monkeypatch)
    calls = {"cors": 0, "path": 0}
    monkeypatch.setattr(
        cli, "probe_cors", lambda url, origin, timeout=10.0: calls.__setitem__("cors", calls["cors"] + 1) or _fetch_result({})
    )
    monkeypatch.setattr(
        cli, "probe_path", lambda url, path, timeout=10.0: calls.__setitem__("path", calls["path"] + 1) or _fetch_result({}, status=404)
    )

    report = cli.run_audit("https://example.com", active_probes=False)

    assert calls == {"cors": 0, "path": 0}
    assert not any(c["category"] == "cors" for c in report["checks"])


def test_run_audit_raises_connection_error_on_fetch_failure(monkeypatch):
    monkeypatch.setattr(
        cli, "fetch",
        lambda url, timeout=10.0, **kw: FetchResult(
            url=url, final_url=url, status=0, headers={}, raw_header_items=[], body=b"",
            error="Name or service not known",
        ),
    )
    try:
        cli.run_audit("https://nonexistent.invalid")
        assert False, "expected ConnectionError"
    except ConnectionError as exc:
        assert "nonexistent.invalid" in str(exc)


def test_main_exit_codes(monkeypatch, capsys):
    _patch_clean_target(monkeypatch)
    exit_code = cli.main(["https://example.com", "--no-color"])
    assert exit_code == cli.EXIT_CLEAN
    assert "Web Security Auditor" in capsys.readouterr().out


def test_main_writes_json_report(monkeypatch, tmp_path):
    _patch_clean_target(monkeypatch)
    json_out = tmp_path / "report.json"
    cli.main(["https://example.com", "--json-out", str(json_out)])
    assert json_out.exists()


def test_main_returns_error_exit_code_on_connection_failure(monkeypatch, capsys):
    monkeypatch.setattr(
        cli, "fetch",
        lambda url, timeout=10.0, **kw: FetchResult(
            url=url, final_url=url, status=0, headers={}, raw_header_items=[], body=b"", error="timed out",
        ),
    )
    exit_code = cli.main(["https://nonexistent.invalid"])
    assert exit_code == cli.EXIT_ERROR
    assert "error" in capsys.readouterr().err
