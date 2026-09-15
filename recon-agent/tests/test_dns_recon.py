import pytest

from recon_agent.dns_recon import enumerate_subdomains, load_wordlist, resolve_host


def test_resolve_host_success():
    result = resolve_host("example.com", resolver=lambda h: "93.184.216.34")
    assert result.resolved is True
    assert result.ip == "93.184.216.34"
    assert result.error is None


def test_resolve_host_failure():
    def failing_resolver(hostname):
        raise OSError("Name or service not known")

    result = resolve_host("not-a-real-host.invalid", resolver=failing_resolver)
    assert result.resolved is False
    assert result.ip is None
    assert "not known" in result.error


def test_enumerate_subdomains_filters_unresolved():
    resolvable = {"www.example.com": "1.2.3.4", "api.example.com": "1.2.3.5"}

    def resolver(hostname):
        if hostname in resolvable:
            return resolvable[hostname]
        raise OSError("NXDOMAIN")

    results = enumerate_subdomains("example.com", ["www", "api", "doesnotexist"], resolver=resolver)
    found = {r.subdomain: r.ip for r in results}
    assert found == {"www.example.com": "1.2.3.4", "api.example.com": "1.2.3.5"}


def test_enumerate_subdomains_respects_limit():
    calls = []

    def resolver(hostname):
        calls.append(hostname)
        return "1.2.3.4"

    enumerate_subdomains("example.com", ["a", "b", "c", "d"], resolver=resolver, limit=2)
    assert calls == ["a.example.com", "b.example.com"]


def test_load_wordlist_strips_and_skips_comments(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("www\n# a comment\n\nadmin\n")
    assert load_wordlist(str(path)) == ["www", "admin"]
