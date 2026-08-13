from recon_agent.vuln_kb import VulnKnowledgeBase


def test_lookup_matches_exact_version():
    kb = VulnKnowledgeBase()
    matches = kb.lookup("vsftpd", "2.3.4")
    assert len(matches) == 1
    assert matches[0].cve == "CVE-2011-2523"
    assert matches[0].severity == "critical"


def test_lookup_matches_version_regex():
    kb = VulnKnowledgeBase()
    matches = kb.lookup("OpenSSH", "7.2p2")
    cves = {m.cve for m in matches}
    assert "CVE-2016-6210" in cves


def test_lookup_is_case_insensitive():
    kb = VulnKnowledgeBase()
    matches = kb.lookup("VSFTPD", "2.3.4")
    assert len(matches) == 1


def test_lookup_no_match_for_patched_version():
    kb = VulnKnowledgeBase()
    matches = kb.lookup("vsftpd", "3.0.5")
    assert matches == []


def test_lookup_unknown_service_returns_empty():
    kb = VulnKnowledgeBase()
    assert kb.lookup("SomeMadeUpDaemon", "1.0") == []


def test_lookup_without_version_returns_empty():
    kb = VulnKnowledgeBase()
    assert kb.lookup("vsftpd", None) == []


def test_lookup_without_service_returns_empty():
    kb = VulnKnowledgeBase()
    assert kb.lookup(None, "2.3.4") == []


def test_vuln_match_to_dict_roundtrips_fields():
    kb = VulnKnowledgeBase()
    match = kb.lookup("Apache", "2.4.49", port=8080)[0]
    d = match.to_dict()
    assert d["cve"] == "CVE-2021-41773"
    assert d["port"] == 8080
    assert d["service"] == "Apache"
