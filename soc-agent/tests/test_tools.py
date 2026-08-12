from soc_agent.tools import (
    extract_indicators,
    ioc_lookup,
    dns_lookup,
    mitre_lookup,
    search_logs,
    get_asset_criticality,
)


def test_extract_indicators_finds_ip_and_domain():
    text = "Beacon from 10.20.4.17 to update-service-cdn.net over HTTPS."
    result = extract_indicators(text)
    assert "10.20.4.17" in result["ips"]
    assert "update-service-cdn.net" in result["domains"]


def test_extract_indicators_does_not_double_count_ip_as_domain():
    result = extract_indicators("Connection to 185.220.101.1 only.")
    assert result["ips"] == ["185.220.101.1"]
    assert result["domains"] == []


def test_extract_indicators_filters_filenames_and_dotted_usernames():
    text = "powershell.exe spawned by explorer.exe, reported by j.morales."
    result = extract_indicators(text)
    assert result["domains"] == []


def test_ioc_lookup_known_malicious():
    hit = ioc_lookup("update-service-cdn.net")
    assert hit["found"] is True
    assert hit["verdict"] == "malicious"


def test_ioc_lookup_unknown_indicator():
    hit = ioc_lookup("totally-unseen-domain.example")
    assert hit["found"] is False
    assert hit["verdict"] == "unknown"


def test_ioc_lookup_is_case_insensitive():
    hit = ioc_lookup("UPDATE-SERVICE-CDN.NET")
    assert hit["found"] is True


def test_dns_lookup_returns_registration_metadata():
    hit = dns_lookup("update-service-cdn.net")
    assert hit["found"] is True
    assert hit["age_days"] < 30
    assert "185.220.101.1" in hit["a_records"]


def test_dns_lookup_unknown_domain():
    hit = dns_lookup("no-such-domain.example")
    assert hit["found"] is False


def test_mitre_lookup_matches_beaconing():
    hit = mitre_lookup("beacon")
    ids = {m["id"] for m in hit["matches"]}
    assert "T1071.001" in ids


def test_mitre_lookup_no_match():
    hit = mitre_lookup("gibberish-behavior-xyz")
    assert hit["matches"] == []


def test_search_logs_finds_matching_lines():
    result = search_logs("185.220.101.1")
    assert result["match_count"] >= 1
    assert all("185.220.101.1" in line for line in result["lines"])


def test_search_logs_no_match():
    result = search_logs("no-such-string-in-logs")
    assert result["match_count"] == 0


def test_get_asset_criticality_known_host():
    hit = get_asset_criticality("SRV-DB-PROD-02")
    assert hit["found"] is True
    assert hit["criticality"] == "critical"


def test_get_asset_criticality_unknown_host():
    hit = get_asset_criticality("UNKNOWN-HOST-99")
    assert hit["found"] is False
    assert hit["criticality"] == "unknown"
