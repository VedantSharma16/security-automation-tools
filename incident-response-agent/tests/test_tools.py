from ir_agent.tools import (
    check_cve,
    check_domain_reputation,
    check_ip_reputation,
    default_store,
    lookup_attack_technique,
)


def test_check_ip_reputation_hit():
    result = check_ip_reputation("185.220.101.1")
    assert result.malicious is True
    assert "Tor exit node" in result.summary
    assert result.detail["confidence"] == "high"


def test_check_ip_reputation_miss():
    result = check_ip_reputation("8.8.8.8")
    assert result.malicious is False
    assert result.detail == {}


def test_check_domain_reputation_hit_and_miss():
    hit = check_domain_reputation("secure-login-update.com")
    assert hit.malicious is True

    miss = check_domain_reputation("example.com")
    assert miss.malicious is False


def test_check_cve_known_exploited_is_malicious():
    result = check_cve("CVE-2021-44228")
    assert result.malicious is True
    assert result.detail["known_exploited"] is True
    assert "Log4Shell" in result.summary


def test_check_cve_case_insensitive_and_unknown():
    result = check_cve("cve-2021-44228")
    assert result.detail["name"] == "Log4Shell"

    unknown = check_cve("CVE-1999-0001")
    assert unknown.malicious is False
    assert "not found" in unknown.summary


def test_lookup_attack_technique_matches_brute_force():
    result = lookup_attack_technique("Many failed login attempts followed by a successful brute force login.")
    assert "T1110" in result.summary
    assert result.detail["id"] == "T1110"


def test_lookup_attack_technique_no_match_returns_low_confidence():
    result = lookup_attack_technique("Employee onboarding paperwork was completed on time.")
    assert result.detail == {}
    assert "No ATT&CK technique" in result.summary


def test_default_store_is_cached_singleton():
    assert default_store() is default_store()
