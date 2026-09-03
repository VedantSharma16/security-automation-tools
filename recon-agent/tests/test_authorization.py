import socket

import pytest

from recon_agent.authorization import AuthorizationError, check_authorization, is_private_target


def test_loopback_is_private():
    assert is_private_target("127.0.0.1")


def test_private_ranges_are_private():
    assert is_private_target("192.168.1.10")
    assert is_private_target("10.0.0.5")
    assert is_private_target("172.16.5.5")


def test_public_ip_is_not_private():
    assert not is_private_target("93.184.216.34")


def test_domain_resolving_to_private_ip_is_private(monkeypatch):
    monkeypatch.setattr("recon_agent.authorization.socket.gethostbyname", lambda h: "10.0.0.5")
    assert is_private_target("internal.lab")


def test_unresolvable_domain_is_not_private(monkeypatch):
    def raise_gaierror(host):
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr("recon_agent.authorization.socket.gethostbyname", raise_gaierror)
    assert not is_private_target("doesnotexist.invalid")


def test_check_authorization_allows_private_target_without_confirmation():
    check_authorization("127.0.0.1", confirmed=False)


def test_check_authorization_blocks_public_target_without_confirmation(monkeypatch):
    monkeypatch.setattr("recon_agent.authorization.socket.gethostbyname", lambda h: "93.184.216.34")
    with pytest.raises(AuthorizationError):
        check_authorization("example.com", confirmed=False)


def test_check_authorization_allows_public_target_with_confirmation(monkeypatch):
    monkeypatch.setattr("recon_agent.authorization.socket.gethostbyname", lambda h: "93.184.216.34")
    check_authorization("example.com", confirmed=True)
