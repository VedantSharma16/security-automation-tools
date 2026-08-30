from recon_agent.fixtures import load_fixture, make_probe_tls_fn, make_probe_url_fn


def test_load_fixture(tmp_path):
    path = tmp_path / "fixture.json"
    path.write_text('{"https": {"ok": true, "status_code": 200, "headers": {}}}')
    data = load_fixture(path)
    assert data["https"]["status_code"] == 200


def test_probe_url_fn_selects_by_scheme():
    fixture = {
        "https": {"ok": True, "status_code": 200, "headers": {"A": "1"}},
        "http": {"ok": False, "error": "redirected"},
    }
    probe_url = make_probe_url_fn(fixture)

    https_result = probe_url("https://example.com")
    http_result = probe_url("http://example.com")

    assert https_result.ok is True
    assert https_result.status_code == 200
    assert https_result.headers == {"A": "1"}
    assert http_result.ok is False
    assert http_result.error == "redirected"


def test_probe_url_fn_missing_scheme_returns_not_ok():
    probe_url = make_probe_url_fn({})
    result = probe_url("https://example.com")
    assert result.ok is False


def test_probe_tls_fn_returns_fixture_data():
    fixture = {"tls": {"ok": True, "version": "TLSv1.3", "days_until_expiry": 10}}
    probe_tls = make_probe_tls_fn(fixture)
    result = probe_tls("example.com")
    assert result.version == "TLSv1.3"
    assert result.days_until_expiry == 10


def test_probe_tls_fn_missing_fixture_returns_not_ok():
    probe_tls = make_probe_tls_fn({})
    result = probe_tls("example.com")
    assert result.ok is False
