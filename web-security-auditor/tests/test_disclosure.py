from webaudit import disclosure


def test_no_banners_passes():
    results = disclosure.analyze_banners({})
    assert len(results) == 1
    assert results[0].status == "pass"


def test_server_banner_warns():
    results = disclosure.analyze_banners({"server": "nginx/1.18.0"})
    assert results[0].status == "warn"
    assert "nginx/1.18.0" in results[0].detail


def test_multiple_banner_headers_each_reported():
    results = disclosure.analyze_banners(
        {"server": "Apache/2.4.1", "x-powered-by": "PHP/7.2.0"}
    )
    ids = {r.id for r in results}
    assert ids == {"banner:server", "banner:x-powered-by"}


def test_exposed_sensitive_path_fails():
    results = disclosure.analyze_probed_paths({"/.env": 200})
    assert results[0].status == "fail"
    assert results[0].severity == "high"


def test_blocked_sensitive_path_passes():
    results = disclosure.analyze_probed_paths({"/.env": 404})
    assert results[0].status == "pass"


def test_security_txt_published_is_informational_pass():
    results = disclosure.analyze_probed_paths({"/.well-known/security.txt": 200})
    assert results[0].status == "pass"
    assert results[0].severity == "info"


def test_security_txt_missing_is_still_a_pass():
    results = disclosure.analyze_probed_paths({"/.well-known/security.txt": 404})
    assert results[0].status == "pass"
