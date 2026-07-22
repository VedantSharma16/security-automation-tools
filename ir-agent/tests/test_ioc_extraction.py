from ir_agent.tools.ioc_extraction import extract_iocs, refang, total_indicator_count


def test_refang_reverses_common_defanging():
    assert refang("hxxps://evil[.]com/path") == "https://evil.com/path"
    assert refang("185[.]220[.]101[.]45") == "185.220.101.45"


def test_extracts_ipv4_and_flags_private():
    result = extract_iocs("Beacon to 91.219.236.18, internal probe from 192.168.1.5.")
    values = {ip["value"]: ip["private_or_reserved"] for ip in result["ips"]}
    assert values["91.219.236.18"] is False
    assert values["192.168.1.5"] is True


def test_extracts_defanged_ipv4_and_domain():
    text = "Traffic to 185[.]220[.]101[.]45 and evil-c2-panel[.]com was observed."
    result = extract_iocs(text)
    assert any(ip["value"] == "185.220.101.45" for ip in result["ips"])
    assert "evil-c2-panel.com" in result["domains"]


def test_extracts_url_email_hash_and_cve():
    text = (
        "Payload fetched from https://evil-c2-panel.com/stage2.bin by attacker@evil.com. "
        "Dropped hash 44d88612fea8a8f36de82e1278abb02f, exploited CVE-2023-12345."
    )
    result = extract_iocs(text)
    assert "https://evil-c2-panel.com/stage2.bin" in result["urls"]
    assert "attacker@evil.com" in result["emails"]
    assert {"value": "44d88612fea8a8f36de82e1278abb02f", "algorithm": "md5"} in result["hashes"]
    assert "CVE-2023-12345" in result["cves"]


def test_filters_filenames_from_domains():
    result = extract_iocs("Dropped payload was named update.exe on the host.")
    assert "update.exe" not in result["domains"]


def test_total_indicator_count():
    result = extract_iocs("No indicators here, just plain English text.")
    assert total_indicator_count(result) == 0

    # "evil.com" is counted both as the email's domain and as a standalone domain IOC.
    result = extract_iocs("Contact attacker@evil.com about 91.219.236.18.")
    assert total_indicator_count(result) == 3
