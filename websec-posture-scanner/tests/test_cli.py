import json

import pytest

from webscan import cli, fetcher
from webscan.models import ScanTarget, TLSInfo


def _fake_target(url: str) -> ScanTarget:
    return ScanTarget(
        url=url,
        final_url=url,
        status_code=200,
        headers={
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=()",
        },
    )


def _fake_tls(hostname: str, port: int = 443) -> TLSInfo:
    return TLSInfo(
        hostname=hostname,
        port=port,
        protocol_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        not_after="Jan  1 00:00:00 2027 GMT",
        days_until_expiry=365,
        issuer="C=US,O=Example CA",
        subject="CN=example.com",
    )


@pytest.fixture(autouse=True)
def patched_network(monkeypatch):
    monkeypatch.setattr(fetcher, "fetch_target", lambda url, **kw: _fake_target(url))
    monkeypatch.setattr(fetcher, "fetch_tls_info", lambda hostname, **kw: _fake_tls(hostname))


def test_cli_clean_scan_exits_zero(capsys):
    exit_code = cli.main(["https://example.com"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Grade: A" in captured.out


def test_cli_normalizes_bare_hostname():
    assert cli.normalize_url("example.com") == "https://example.com"
    assert cli.normalize_url("http://example.com") == "http://example.com"


def test_cli_writes_json_report(tmp_path):
    out_path = tmp_path / "report.json"
    exit_code = cli.main(["https://example.com", "--json", str(out_path)])
    assert exit_code == 0
    data = json.loads(out_path.read_text())
    assert data["grade"] == "A"


def test_cli_writes_markdown_report(tmp_path):
    out_path = tmp_path / "report.md"
    cli.main(["https://example.com", "--markdown", str(out_path)])
    assert "# Web Security Posture Scan" in out_path.read_text()


def test_cli_fail_below_triggers_nonzero_exit(monkeypatch):
    bad_target = _fake_target("https://example.com")
    bad_target.headers = {}
    monkeypatch.setattr(fetcher, "fetch_target", lambda url, **kw: bad_target)
    exit_code = cli.main(["https://example.com", "--fail-below", "A"])
    assert exit_code == 1


def test_cli_fetch_error_returns_exit_code_two(monkeypatch):
    def _raise(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(fetcher, "fetch_target", _raise)
    exit_code = cli.main(["https://unreachable.example"])
    assert exit_code == 2


def test_cli_no_tls_check_skips_tls_fetch(monkeypatch):
    calls = []
    monkeypatch.setattr(fetcher, "fetch_tls_info", lambda hostname, **kw: calls.append(hostname))
    cli.main(["https://example.com", "--no-tls-check"])
    assert calls == []
