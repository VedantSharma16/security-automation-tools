from attack_surface_mapper import subdomains


SAMPLE_CRTSH = [
    {"name_value": "www.example.com"},
    {"name_value": "*.example.com\napi.example.com"},
    {"name_value": "www.example.com"},  # duplicate
    {"name_value": "example.com"},
    {"name_value": "unrelated.org"},
    {"name_value": "notexample.com"},  # not a subdomain of example.com
]


def test_parse_subdomains_dedupes_and_strips_wildcards():
    names = subdomains.parse_subdomains(SAMPLE_CRTSH, "example.com")
    assert names == ["api.example.com", "example.com", "www.example.com"]


def test_parse_subdomains_excludes_unrelated_domains():
    names = subdomains.parse_subdomains(SAMPLE_CRTSH, "example.com")
    assert "unrelated.org" not in names
    assert "notexample.com" not in names


def test_parse_subdomains_handles_empty_input():
    assert subdomains.parse_subdomains([], "example.com") == []


def test_resolve_returns_ip_map_with_failures():
    def fake_resolver(name):
        if name == "good.example.com":
            return "10.0.0.1"
        raise __import__("socket").gaierror("nope")

    result = subdomains.resolve(
        ["good.example.com", "bad.example.com"], resolver=fake_resolver
    )
    assert result == {"good.example.com": "10.0.0.1", "bad.example.com": None}


def test_resolve_empty_list_short_circuits():
    assert subdomains.resolve([], resolver=lambda n: "1.2.3.4") == {}


def test_discover_full_pipeline():
    def fake_fetcher(domain, timeout):
        assert domain == "example.com"
        return SAMPLE_CRTSH

    def fake_resolver(name):
        return "10.0.0.1" if name == "example.com" else "10.0.0.2"

    result = subdomains.discover(
        "example.com", fetcher=fake_fetcher, resolver=fake_resolver
    )
    names = {s.name: s.ip for s in result}
    assert names["example.com"] == "10.0.0.1"
    assert names["www.example.com"] == "10.0.0.2"


def test_discover_skips_resolution_when_disabled():
    def fake_fetcher(domain, timeout):
        return SAMPLE_CRTSH

    result = subdomains.discover("example.com", fetcher=fake_fetcher, resolve_dns=False)
    assert all(s.ip is None for s in result)


def test_discover_returns_empty_when_fetcher_finds_nothing():
    result = subdomains.discover("example.com", fetcher=lambda d, t: [])
    assert result == []


def test_fetch_crtsh_returns_empty_list_on_network_error(monkeypatch):
    def raise_error(*args, **kwargs):
        raise OSError("network unreachable")

    monkeypatch.setattr(subdomains.urllib.request, "urlopen", raise_error)
    assert subdomains.fetch_crtsh("example.com") == []
