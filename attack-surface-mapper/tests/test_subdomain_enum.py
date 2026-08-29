import requests
import pytest

from asm import subdomain_enum


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc
        self.last_params = None

    def get(self, url, params=None, timeout=None):
        self.last_params = params
        if self._exc:
            raise self._exc
        return self._response


def test_query_crtsh_dedupes_and_strips_wildcards():
    payload = [
        {"name_value": "www.example.com\nexample.com"},
        {"name_value": "*.example.com"},
        {"name_value": "WWW.example.com"},  # different case, same host
    ]
    session = FakeSession(response=FakeResponse(payload))
    result = subdomain_enum.query_crtsh("example.com", session=session)
    assert result == ["example.com", "www.example.com"]
    assert session.last_params == {"q": "%.example.com", "output": "json"}


def test_query_crtsh_raises_on_network_error():
    session = FakeSession(exc=requests.ConnectionError("boom"))
    with pytest.raises(subdomain_enum.SubdomainEnumError):
        subdomain_enum.query_crtsh("example.com", session=session)


def test_query_crtsh_raises_on_bad_json():
    class BadJsonResponse(FakeResponse):
        def json(self):
            raise ValueError("not json")

    session = FakeSession(response=BadJsonResponse([]))
    with pytest.raises(subdomain_enum.SubdomainEnumError):
        subdomain_enum.query_crtsh("example.com", session=session)


def test_build_findings_flags_large_attack_surface():
    subdomains = [f"host{i}.example.com" for i in range(60)]
    findings = subdomain_enum.build_findings("example.com", subdomains)
    titles = {f.title for f in findings}
    assert "Large discoverable attack surface" in titles


def test_build_findings_no_large_surface_flag_for_small_count():
    findings = subdomain_enum.build_findings("example.com", ["www.example.com"])
    titles = {f.title for f in findings}
    assert "Large discoverable attack surface" not in titles
