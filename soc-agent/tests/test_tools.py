import datetime

from soc_agent.tools import (
    TOOL_FUNCTIONS,
    TOOL_SCHEMAS,
    check_process_baseline,
    geoip_lookup,
    lookup_domain_reputation,
    lookup_ip_reputation,
    search_attack_techniques,
    whois_lookup,
)


def test_lookup_ip_reputation_known_malicious():
    result = lookup_ip_reputation("185.220.101.1")
    assert result["verdict"] == "malicious"
    assert result["confidence"] == "high"


def test_lookup_ip_reputation_unknown_ip():
    result = lookup_ip_reputation("1.2.3.4")
    assert result["verdict"] == "unknown"


def test_lookup_domain_reputation_known_malicious():
    result = lookup_domain_reputation("EVIL-C2-PANEL.COM")
    assert result["verdict"] == "malicious"
    assert result["domain"] == "evil-c2-panel.com"


def test_geoip_lookup_known_and_unknown():
    known = geoip_lookup("45.155.205.38")
    assert known["country"] == "Netherlands"
    unknown = geoip_lookup("203.0.113.9")
    assert unknown["country"] == "unknown"


def test_whois_lookup_computes_age_days_from_created_date():
    result = whois_lookup("microsoft.com")
    created = datetime.date.fromisoformat(result["created"])
    expected_age = (datetime.date.today() - created).days
    assert result["age_days"] == expected_age
    assert result["privacy_protected"] is False


def test_whois_lookup_unknown_domain():
    result = whois_lookup("not-a-real-domain-xyz.com")
    assert result["age_days"] is None


def test_check_process_baseline_known_bad_good_and_unrecognized():
    assert check_process_baseline("mimikatz.exe")["status"] == "known_bad"
    assert check_process_baseline("EXPLORER.EXE")["status"] == "known_good"
    assert check_process_baseline("totally_unknown.exe")["status"] == "unrecognized"


def test_search_attack_techniques_returns_relevant_hits_ranked():
    results = search_attack_techniques("encoded powershell scheduled task persistence", top_k=2)
    assert len(results) <= 2
    ids = [r["id"] for r in results]
    assert "T1059" in ids or "T1053" in ids
    if len(results) > 1:
        assert results[0]["relevance"] >= results[1]["relevance"]


def test_search_attack_techniques_no_match_returns_empty():
    assert search_attack_techniques("completely unrelated query zzz qqq") == []


def test_tool_schemas_match_tool_functions():
    schema_names = {schema["name"] for schema in TOOL_SCHEMAS}
    assert schema_names == set(TOOL_FUNCTIONS.keys())
    for schema in TOOL_SCHEMAS:
        assert "description" in schema
        assert schema["input_schema"]["type"] == "object"
        assert "required" in schema["input_schema"]
