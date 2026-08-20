from pathlib import Path

from asm.cve_matcher import VulnRule, load_rules, match_hosts
from asm.nmap_parser import Host, Port

DATA = Path(__file__).parent.parent / "data" / "cve_db.json"


def make_rule(**overrides) -> VulnRule:
    defaults = dict(
        rule_id="TEST-1",
        rule_type="cve",
        product_aliases=["openssh"],
        title="Test rule",
        description="desc",
        cvss=7.5,
        severity="high",
        exploit_available=False,
        reference="https://example.invalid",
        version_min="7.0",
        version_max="7.5",
    )
    defaults.update(overrides)
    return VulnRule(**defaults)


def test_load_rules_parses_bundled_database():
    rules = load_rules(DATA)
    assert len(rules) > 0
    assert all(isinstance(r, VulnRule) for r in rules)


def test_cve_rule_matches_version_in_range():
    host = Host(address="10.0.0.1", ports=[
        Port(port_id=22, protocol="tcp", state="open", service="ssh", product="OpenSSH", version="7.2p2")
    ])
    matches = match_hosts([host], [make_rule()])
    assert len(matches) == 1
    assert matches[0].confidence == "confirmed"


def test_cve_rule_does_not_match_version_out_of_range():
    host = Host(address="10.0.0.1", ports=[
        Port(port_id=22, protocol="tcp", state="open", service="ssh", product="OpenSSH", version="9.0p1")
    ])
    matches = match_hosts([host], [make_rule()])
    assert matches == []


def test_cve_rule_is_unconfirmed_when_version_missing():
    host = Host(address="10.0.0.1", ports=[
        Port(port_id=22, protocol="tcp", state="open", service="ssh", product="OpenSSH", version="")
    ])
    matches = match_hosts([host], [make_rule()])
    assert len(matches) == 1
    assert matches[0].confidence == "unconfirmed"


def test_insecure_protocol_rule_matches_regardless_of_version():
    rule = make_rule(
        rule_id="INSECURE-TEST",
        rule_type="insecure_protocol",
        product_aliases=["telnet"],
        version_min=None,
        version_max=None,
    )
    host = Host(address="10.0.0.1", ports=[
        Port(port_id=23, protocol="tcp", state="open", service="telnet", product="", version="")
    ])
    matches = match_hosts([host], [rule])
    assert len(matches) == 1
    assert matches[0].confidence == "confirmed"


def test_closed_ports_are_never_matched():
    host = Host(address="10.0.0.1", ports=[
        Port(port_id=22, protocol="tcp", state="closed", service="ssh", product="OpenSSH", version="7.2p2")
    ])
    matches = match_hosts([host], [make_rule()])
    assert matches == []


def test_unrelated_product_does_not_match():
    host = Host(address="10.0.0.1", ports=[
        Port(port_id=80, protocol="tcp", state="open", service="http", product="nginx", version="1.25.3")
    ])
    matches = match_hosts([host], [make_rule()])
    assert matches == []


def test_bundled_db_flags_known_vulnerable_ftp_daemon():
    rules = load_rules(DATA)
    host = Host(address="10.0.0.1", ports=[
        Port(port_id=21, protocol="tcp", state="open", service="ftp", product="vsftpd", version="2.3.4")
    ])
    matches = match_hosts([host], rules)
    assert any(m.rule.rule_id == "CVE-2011-2523" for m in matches)
