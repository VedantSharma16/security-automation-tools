from soc_agent.extractor import extract_seed_indicators


def test_extracts_public_ip_and_domain_and_process():
    text = "powershell.exe beaconed to evil-c2-panel.com (185.220.101.1) on port 443."
    seed = extract_seed_indicators(text)
    assert "185.220.101.1" in seed["ips"]
    assert "evil-c2-panel.com" in seed["domains"]
    assert "powershell.exe" in seed["processes"]


def test_filters_private_and_loopback_ips():
    text = "Internal traffic from 10.0.0.5 and 192.168.1.1 and 127.0.0.1 to 8.8.8.8."
    seed = extract_seed_indicators(text)
    assert seed["ips"] == ["8.8.8.8"]


def test_deduplicates_indicators():
    text = "185.220.101.1 beaconed twice: 185.220.101.1 then 185.220.101.1 again."
    seed = extract_seed_indicators(text)
    assert seed["ips"] == ["185.220.101.1"]


def test_recognizes_bare_named_processes():
    text = "sshd accepted a connection; mimikatz was later observed."
    seed = extract_seed_indicators(text)
    assert "sshd" in seed["processes"]
    assert "mimikatz" in seed["processes"]


def test_empty_text_returns_empty_lists():
    seed = extract_seed_indicators("Nothing interesting here.")
    assert seed == {"ips": [], "domains": [], "processes": []}
