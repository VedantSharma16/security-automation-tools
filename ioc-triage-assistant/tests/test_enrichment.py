import pytest

from ioc_triage.enrichment import enrich_indicator, enrich_indicators, load_threat_intel
from ioc_triage.extractor import Indicator


@pytest.fixture(scope="module")
def threat_intel():
    return load_threat_intel()


def test_load_threat_intel_returns_keyed_map(threat_intel):
    assert ("ipv4", "185.220.101.1") in threat_intel
    assert ("domain", "evil-c2-panel.com") in threat_intel


def test_known_malicious_ip_is_flagged(threat_intel):
    indicator = Indicator(value="185.220.101.1", category="ipv4")
    result = enrich_indicator(indicator, threat_intel)
    assert result.is_known_malicious is True
    assert result.confidence == "high"


def test_lookup_is_case_insensitive(threat_intel):
    indicator = Indicator(value="EVIL-C2-PANEL.COM", category="domain")
    result = enrich_indicator(indicator, threat_intel)
    assert result.is_known_malicious is True


def test_unknown_indicator_is_not_flagged(threat_intel):
    indicator = Indicator(value="8.8.8.8", category="ipv4")
    result = enrich_indicator(indicator, threat_intel)
    assert result.is_known_malicious is False
    assert "No match" in result.notes


def test_private_ip_is_annotated_but_not_malicious(threat_intel):
    indicator = Indicator(value="10.20.4.17", category="ipv4")
    result = enrich_indicator(indicator, threat_intel)
    assert result.is_known_malicious is False
    assert "private" in result.notes.lower()


def test_enrich_indicators_batch(threat_intel):
    indicators = [
        Indicator(value="185.220.101.1", category="ipv4"),
        Indicator(value="8.8.8.8", category="ipv4"),
    ]
    results = enrich_indicators(indicators, threat_intel)
    assert len(results) == 2
    assert results[0].is_known_malicious is True
    assert results[1].is_known_malicious is False
