from ir_agent.tools.enrichment import enrich_indicators, known_malicious_hits
from ir_agent.tools.ioc_extraction import extract_iocs


def test_enrich_flags_known_malicious_ip_and_hash():
    text = (
        "Beacon to 45.148.10.94 and download from http://45.148.10.94/update.php, "
        "hash e99a18c428cb38d5f260853678922e03, clean ip 8.8.8.8"
    )
    indicators = extract_iocs(text)
    enrichment = enrich_indicators(indicators)

    by_value = {entry["value"]: entry for entry in enrichment}
    assert by_value["45.148.10.94"]["is_known_malicious"] is True
    assert by_value["45.148.10.94"]["confidence"] == "high"
    assert by_value["8.8.8.8"]["is_known_malicious"] is False
    assert by_value["e99a18c428cb38d5f260853678922e03"]["is_known_malicious"] is True


def test_enrich_returns_one_entry_per_checked_indicator():
    indicators = extract_iocs("Clean traffic from 8.8.8.8 only.")
    enrichment = enrich_indicators(indicators)
    assert len(enrichment) == 1
    assert enrichment[0]["is_known_malicious"] is False


def test_known_malicious_hits_filters_correctly():
    indicators = extract_iocs("45.148.10.94 talked to 8.8.8.8.")
    enrichment = enrich_indicators(indicators)
    hits = known_malicious_hits(enrichment)
    assert len(hits) == 1
    assert hits[0]["value"] == "45.148.10.94"


def test_enrich_handles_no_indicators():
    indicators = extract_iocs("Nothing interesting here.")
    assert enrich_indicators(indicators) == []
