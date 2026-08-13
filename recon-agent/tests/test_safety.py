import pytest

from recon_agent.safety import UnauthorizedTargetError, check_authorization, is_private_target


def test_loopback_ip_is_private():
    assert is_private_target("127.0.0.1") is True


def test_rfc1918_ip_is_private():
    assert is_private_target("192.168.1.10") is True
    assert is_private_target("10.0.0.5") is True


def test_public_ip_is_not_private():
    assert is_private_target("8.8.8.8") is False


def test_localhost_hostname_resolves_private():
    assert is_private_target("localhost") is True


def test_unresolvable_hostname_is_not_private():
    assert is_private_target("this-host-does-not-resolve.invalid") is False


def test_check_authorization_allows_loopback_without_flag():
    check_authorization("127.0.0.1", authorized_flag=False)  # should not raise


def test_check_authorization_blocks_public_target_without_flag():
    with pytest.raises(UnauthorizedTargetError):
        check_authorization("8.8.8.8", authorized_flag=False)


def test_check_authorization_allows_public_target_with_flag():
    check_authorization("8.8.8.8", authorized_flag=True)  # should not raise


def test_check_authorization_blocks_unresolvable_hostname_without_flag():
    with pytest.raises(UnauthorizedTargetError):
        check_authorization("this-host-does-not-resolve.invalid", authorized_flag=False)
