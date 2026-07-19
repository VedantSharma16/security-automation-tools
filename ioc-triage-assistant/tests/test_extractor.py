from ioc_triage.extractor import extract_iocs, refang


def test_refang_reverses_common_defanging():
    assert refang("hxxps://evil[.]com/path") == "https://evil.com/path"
    assert refang("185[.]220[.]101[.]1") == "185.220.101.1"
    assert refang("user[at]example.com") == "user@example.com"


def test_extracts_ipv4():
    indicators = extract_iocs("Beacon observed to 185.220.101.1 on port 443.")
    values = {(i.category, i.value) for i in indicators}
    assert ("ipv4", "185.220.101.1") in values


def test_extracts_defanged_ipv4_and_domain():
    text = "Traffic to 185[.]220[.]101[.]1 and evil-c2-panel[.]com was observed."
    indicators = extract_iocs(text)
    values = {(i.category, i.value) for i in indicators}
    assert ("ipv4", "185.220.101.1") in values
    assert ("domain", "evil-c2-panel.com") in values


def test_extracts_url_email_hashes_and_cve():
    text = (
        "Payload fetched from https://evil-c2-panel.com/stage2.bin by attacker@evil.com. "
        "Dropped hash 44d88612fea8a8f36de82e1278abb02f exploited CVE-2023-12345."
    )
    indicators = extract_iocs(text)
    categories = {i.category for i in indicators}
    values = {i.value for i in indicators}
    assert "url" in categories
    assert "email" in categories
    assert "md5" in categories
    assert "cve" in categories
    assert "https://evil-c2-panel.com/stage2.bin" in values
    assert "attacker@evil.com" in values
    assert "CVE-2023-12345" in values


def test_deduplicates_case_insensitively():
    text = "Contact Attacker@Evil.com and attacker@evil.com about evil.com"
    indicators = extract_iocs(text)
    emails = [i for i in indicators if i.category == "email"]
    assert len(emails) == 1


def test_no_false_positive_ipv4_from_version_string():
    indicators = extract_iocs("Client reported Python 3.11.15 in the user agent string.")
    ipv4s = [i for i in indicators if i.category == "ipv4"]
    assert ipv4s == []


def test_empty_text_returns_no_indicators():
    assert extract_iocs("") == []


def test_no_false_positive_domains_from_filenames_and_usernames():
    text = (
        "ParentImage: C:\\Windows\\explorer.exe launched schtasks.exe. "
        "User: j.morales reported the issue."
    )
    indicators = extract_iocs(text)
    domains = {i.value.lower() for i in indicators if i.category == "domain"}
    assert "explorer.exe" not in domains
    assert "schtasks.exe" not in domains
    assert "j.morales" not in domains


def test_known_tld_domain_still_extracted_alongside_filenames():
    text = "explorer.exe connected to evil-c2-panel.com"
    indicators = extract_iocs(text)
    domains = {i.value.lower() for i in indicators if i.category == "domain"}
    assert domains == {"evil-c2-panel.com"}
