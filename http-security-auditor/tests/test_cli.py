import json

import http_audit.cli as cli
from http_audit.fetcher import FetchError, HttpResponse


def _patch_run_audit_hardened(monkeypatch):
    def fake_run_audit(url, transport=None, check_exposed=False, narrator=None):
        from http_audit.audit import run_audit as real_run_audit
        from http_audit.llm_narrative import LLMNarrator

        def transport_fn(u):
            return HttpResponse(
                url=u,
                status=200,
                headers={
                    "strict-transport-security": "max-age=63072000",
                    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "geolocation=()",
                },
            )

        return real_run_audit(url, transport=transport_fn, check_exposed=check_exposed, narrator=LLMNarrator(api_key=None))

    monkeypatch.setattr(cli, "run_audit", fake_run_audit)


def test_cli_human_output(monkeypatch, capsys):
    _patch_run_audit_hardened(monkeypatch)
    exit_code = cli.main(["--url", "https://example.com/"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Grade:" in out
    assert "Findings" in out


def test_cli_json_output(monkeypatch, capsys):
    _patch_run_audit_hardened(monkeypatch)
    exit_code = cli.main(["--url", "https://example.com/", "--json"])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["url"] == "https://example.com/"
    assert "findings" in payload


def test_cli_markdown_output(monkeypatch, capsys):
    _patch_run_audit_hardened(monkeypatch)
    exit_code = cli.main(["--url", "https://example.com/", "--markdown"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert out.startswith("# HTTP Security Audit")


def test_cli_requires_url():
    try:
        cli.main([])
        assert False, "expected SystemExit for missing --url"
    except SystemExit as exc:
        assert exc.code != 0


def test_cli_reports_fetch_errors(monkeypatch, capsys):
    def fake_run_audit(url, transport=None, check_exposed=False, narrator=None):
        raise FetchError(f"Failed to reach {url}: simulated failure")

    monkeypatch.setattr(cli, "run_audit", fake_run_audit)
    exit_code = cli.main(["--url", "https://unreachable.example.com/"])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "simulated failure" in err
