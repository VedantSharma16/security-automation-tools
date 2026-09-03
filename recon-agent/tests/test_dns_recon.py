import socket

from recon_agent import dns_recon


def test_resolve_success(monkeypatch):
    monkeypatch.setattr(dns_recon.socket, "gethostbyname", lambda h: "1.2.3.4")
    assert dns_recon.resolve("example.com") == "1.2.3.4"


def test_resolve_failure_returns_none(monkeypatch):
    def raise_gaierror(host):
        raise socket.gaierror("nope")

    monkeypatch.setattr(dns_recon.socket, "gethostbyname", raise_gaierror)
    assert dns_recon.resolve("nope.invalid") is None


def test_enumerate_subdomains_uses_injected_resolver():
    fake_records = {"www.example.com": "1.1.1.1", "admin.example.com": "2.2.2.2"}

    def fake_resolver(host):
        return fake_records.get(host)

    found = dns_recon.enumerate_subdomains(
        "example.com", ["www", "admin", "ghost"], resolver=fake_resolver
    )
    assert found == fake_records


def test_enumerate_subdomains_empty_wordlist_returns_empty():
    assert dns_recon.enumerate_subdomains("example.com", [], resolver=lambda h: "1.1.1.1") == {}
