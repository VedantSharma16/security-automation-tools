from ir_agent.entities import extract_entities


def test_extracts_ip_domain_and_cve():
    text = (
        "Beacon traffic to 45.155.205.28 and cdn-analytics-sync.net, "
        "exploiting CVE-2021-44228."
    )
    entities = extract_entities(text)
    assert entities.ips == ["45.155.205.28"]
    assert entities.domains == ["cdn-analytics-sync.net"]
    assert entities.cves == ["CVE-2021-44228"]


def test_dedupes_and_preserves_order():
    text = "Contact from 10.0.0.5 again: 10.0.0.5. Also 10.0.0.9."
    entities = extract_entities(text)
    assert entities.ips == ["10.0.0.5", "10.0.0.9"]


def test_ignores_domain_like_strings_with_unknown_tld():
    text = "The process explorer.exe launched schtasks.exe on the host."
    entities = extract_entities(text)
    assert entities.domains == []


def test_normalizes_cve_case():
    entities = extract_entities("Exploited via cve-2020-1472 on the DC.")
    assert entities.cves == ["CVE-2020-1472"]


def test_is_empty():
    assert extract_entities("Routine login, nothing notable.").is_empty()
    assert not extract_entities("Reach out to 10.0.0.5").is_empty()
