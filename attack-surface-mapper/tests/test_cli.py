from __future__ import annotations

import json

from asmapper import cli
from asmapper.fetcher import FetchResult


def _make_fetch_fn(root_headers, root_body=""):
    def _fetch(url, timeout=8.0, method="GET"):
        if url == "https://example.com":
            return FetchResult(url=url, status=200, headers=root_headers, body=root_body)
        return FetchResult(url=url, status=404, headers={}, body="not found")

    return _fetch


def test_cli_clean_target_exits_zero(monkeypatch, capsys):
    good_headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    monkeypatch.setattr(cli, "fetch", _make_fetch_fn(good_headers))

    exit_code = cli.main(["https://example.com", "--offline"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "https://example.com" in out
    assert "Risk score        : 0/100" in out


def test_cli_risky_target_exits_nonzero(monkeypatch, capsys):
    risky_headers = {"Set-Cookie": "session=abc123; Path=/"}  # no CSP/HSTS/etc, no cookie flags
    monkeypatch.setattr(cli, "fetch", _make_fetch_fn(risky_headers))

    exit_code = cli.main(["https://example.com", "--offline"])
    out = capsys.readouterr().out

    assert exit_code == 1
    assert "high" in out or "critical" in out


def test_cli_writes_json_and_markdown_reports(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "fetch", _make_fetch_fn({}))
    json_path = tmp_path / "out.json"
    md_path = tmp_path / "out.md"

    cli.main(["https://example.com", "--offline", "--json-out", str(json_path), "--md-out", str(md_path)])
    capsys.readouterr()

    data = json.loads(json_path.read_text())
    assert data["target"] == "https://example.com"
    assert "# Attack Surface Report" in md_path.read_text()


def test_cli_min_severity_filters_console_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "fetch", _make_fetch_fn({}))

    cli.main(["https://example.com", "--offline", "--min-severity", "critical"])
    out = capsys.readouterr().out
    assert "No findings at or above the selected severity." in out


def test_cli_enable_exposure_checks_runs_the_extra_module(monkeypatch, capsys):
    monkeypatch.setattr(cli, "fetch", _make_fetch_fn({}))

    cli.main(["https://example.com", "--offline", "--enable-exposure-checks"])
    out = capsys.readouterr().out
    assert "run_exposure_check" in out


def test_cli_offline_flag_avoids_agentic_path_even_with_api_key(monkeypatch, capsys):
    monkeypatch.setattr(cli, "fetch", _make_fetch_fn({}))

    exit_code = cli.main(["https://example.com", "--offline", "--api-key", "sk-should-be-ignored"])
    out = capsys.readouterr().out

    assert exit_code in (0, 1)
    assert "Planner mode      : offline" in out


def test_cli_no_color_strips_ansi(monkeypatch, capsys):
    monkeypatch.setattr(cli, "fetch", _make_fetch_fn({"Set-Cookie": "session=abc"}))

    cli.main(["https://example.com", "--offline", "--no-color"])
    out = capsys.readouterr().out
    assert "\033[" not in out
