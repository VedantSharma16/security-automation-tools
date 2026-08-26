import json

import httpsec.cli as cli
from httpsec.models import FetchResult, TLSInfo


def _fetch_result(headers=None, set_cookies=None, final_url="https://example.com/"):
    return FetchResult(
        url=final_url,
        final_url=final_url,
        status_code=200,
        headers=headers or {},
        set_cookies=set_cookies or [],
        redirect_chain=[],
        elapsed_ms=12.3,
    )


def _healthy_tls_info():
    return TLSInfo(
        protocol="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        not_before="Jan  1 00:00:00 2025 GMT",
        not_after="Jan  1 00:00:00 2030 GMT",
        days_until_expiry=365,
        subject_cn="example.com",
        issuer_cn="Some CA",
        san=["example.com"],
    )


def test_run_audit_aggregates_all_analyzers(monkeypatch):
    monkeypatch.setattr(
        cli.fetcher,
        "fetch",
        lambda url, timeout=10.0, insecure=False: _fetch_result(
            headers={}, set_cookies=["sessionid=abc"]
        ),
    )
    monkeypatch.setattr(
        cli.fetcher,
        "fetch_with_origin",
        lambda url, origin, timeout=10.0, insecure=False: _fetch_result(
            headers={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
        ),
    )
    monkeypatch.setattr(
        cli.tls_inspector, "inspect", lambda hostname, port=443, timeout=10.0: _healthy_tls_info()
    )

    target, findings = cli.run_audit("https://example.com/")
    ids = {f.id for f in findings}

    assert target == "https://example.com/"
    assert "header-missing-hsts" in ids  # from headers.py
    assert "cookie-missing-secure" in ids  # from cookies.py
    assert "cors-reflects-arbitrary-origin" in ids  # from cors.py
    assert not any(i.startswith("tls-") for i in ids)  # healthy TLS -> no tls findings


def test_run_audit_skips_tls_when_disabled(monkeypatch):
    monkeypatch.setattr(cli.fetcher, "fetch", lambda url, timeout=10.0, insecure=False: _fetch_result())
    monkeypatch.setattr(
        cli.fetcher,
        "fetch_with_origin",
        lambda url, origin, timeout=10.0, insecure=False: _fetch_result(),
    )

    def _boom(*a, **k):
        raise AssertionError("tls_inspector.inspect should not be called")

    monkeypatch.setattr(cli.tls_inspector, "inspect", _boom)

    _, findings = cli.run_audit("https://example.com/", check_tls=False)
    assert isinstance(findings, list)  # completes without invoking TLS inspection


def test_run_audit_skips_cors_when_disabled(monkeypatch):
    monkeypatch.setattr(cli.fetcher, "fetch", lambda url, timeout=10.0, insecure=False: _fetch_result())

    def _boom(*a, **k):
        raise AssertionError("fetch_with_origin should not be called")

    monkeypatch.setattr(cli.fetcher, "fetch_with_origin", _boom)
    monkeypatch.setattr(
        cli.tls_inspector, "inspect", lambda hostname, port=443, timeout=10.0: _healthy_tls_info()
    )

    _, findings = cli.run_audit("https://example.com/", check_cors=False)
    assert isinstance(findings, list)


def test_main_exit_code_zero_when_no_findings(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: ("https://example.com/", []))
    rc = cli.main(["https://example.com/", "--no-color"])
    assert rc == 0
    assert "No findings" in capsys.readouterr().out


def test_main_exit_code_one_when_findings_present(monkeypatch, capsys):
    from httpsec.models import Finding

    finding = Finding(
        id="header-missing-hsts",
        category="headers",
        severity="high",
        title="Missing HSTS",
        description="d",
        remediation="r",
    )
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: ("https://example.com/", [finding]))
    rc = cli.main(["https://example.com/", "--no-color"])
    assert rc == 1
    assert "Missing HSTS" in capsys.readouterr().out


def test_main_min_severity_filters_exit_code_but_not_json(monkeypatch, capsys, tmp_path):
    from httpsec.models import Finding

    low_finding = Finding(
        id="header-missing-permissions-policy",
        category="headers",
        severity="info",
        title="info finding",
        description="d",
        remediation="r",
    )
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: ("https://example.com/", [low_finding]))

    json_path = tmp_path / "report.json"
    rc = cli.main(
        ["https://example.com/", "--no-color", "--min-severity", "high", "--json-out", str(json_path)]
    )

    assert rc == 0  # info finding filtered out of the exit-code-relevant view
    payload = json.loads(json_path.read_text())
    assert len(payload["findings"]) == 1  # but still present in the full JSON report


def test_main_returns_two_on_fatal_error(monkeypatch, capsys):
    def _raise(*a, **k):
        raise ConnectionError("boom")

    monkeypatch.setattr(cli, "run_audit", _raise)
    rc = cli.main(["https://unreachable.example/"])
    assert rc == 2
    assert "fatal error" in capsys.readouterr().err
