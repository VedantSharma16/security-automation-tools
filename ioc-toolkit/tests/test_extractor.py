from ioc_toolkit.extractor import extract


def test_extracts_ipv4():
    result = extract("The beacon called back to 203.0.113.42 on port 443.")
    assert "203.0.113.42" in result.by_type("ipv4")


def test_extracts_defanged_ipv4_via_autorefang():
    result = extract("Beacon C2: 203[.]0[.]113[.]42")
    assert "203.0.113.42" in result.by_type("ipv4")


def test_extracts_url_and_does_not_double_count_domain():
    result = extract("Payload hosted at hxxp://malicious-domain[.]net/payload.exe")
    assert result.by_type("url") == ["http://malicious-domain.net/payload.exe"]
    assert result.by_type("domain") == []


def test_extracts_email():
    result = extract("Phishing sent from attacker@evil-corp.com to victim.")
    assert "attacker@evil-corp.com" in result.by_type("email")


def test_extracts_hashes_by_length():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"[:64]
    text = f"MD5: {md5} SHA1: {sha1} SHA256: {sha256}"
    result = extract(text)
    assert result.by_type("md5") == [md5]
    assert result.by_type("sha1") == [sha1]
    assert result.by_type("sha256") == [sha256]


def test_extracts_cve_and_normalizes_case():
    result = extract("Exploited via cve-2024-3094 in the wild.")
    assert result.by_type("cve") == ["CVE-2024-3094"]


def test_extracts_bare_domain():
    result = extract("DNS beacon to update-service.badactor.io every 60 seconds.")
    assert "update-service.badactor.io" in result.by_type("domain")


def test_no_matches_on_clean_text():
    result = extract("This report contains no indicators whatsoever.")
    assert len(result) == 0
    assert result.to_dict()["ipv4"] == []


def test_dedup_within_type():
    result = extract("Seen from 203.0.113.42 and again from 203.0.113.42.")
    assert result.by_type("ipv4").count("203.0.113.42") == 1
    assert result.to_dict()["ipv4"] == ["203.0.113.42"]
