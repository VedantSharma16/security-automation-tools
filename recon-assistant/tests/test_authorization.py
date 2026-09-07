import pytest

from recon_assistant.authorization import AuthorizationError, check_authorization, is_private_or_loopback


def test_private_ip_is_private_or_loopback():
    assert is_private_or_loopback("192.168.1.10")
    assert is_private_or_loopback("10.0.0.5")
    assert is_private_or_loopback("127.0.0.1")


def test_public_ip_is_not_private():
    assert not is_private_or_loopback("8.8.8.8")


def test_private_target_needs_no_confirmation():
    check_authorization("internal.local", "10.0.0.5", confirmed=False)  # must not raise


def test_public_target_without_confirmation_raises():
    with pytest.raises(AuthorizationError):
        check_authorization("example.com", "93.184.216.34", confirmed=False)


def test_public_target_with_confirmation_is_allowed():
    check_authorization("example.com", "93.184.216.34", confirmed=True)  # must not raise
