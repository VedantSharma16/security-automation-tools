from ioc_toolkit.enrichment import enrich, attack_url


def test_enrich_finds_known_tool_case_insensitive():
    hits = enrich("The attacker ran Mimikatz to dump credentials.")
    assert any(h.keyword == "mimikatz" for h in hits)
    hit = next(h for h in hits if h.keyword == "mimikatz")
    assert hit.technique_id == "T1003"
    assert hit.tactic == "Credential Access"


def test_enrich_no_hits_on_benign_text():
    hits = enrich("Quarterly report on network uptime and ticket volume.")
    assert hits == []


def test_enrich_deduplicates_repeated_keyword():
    hits = enrich("powershell.exe launched powershell again with -enc payload, powershell everywhere")
    matches = [h for h in hits if h.keyword == "powershell"]
    assert len(matches) == 1


def test_enrich_handles_tool_without_technique_id():
    hits = enrich("Recon performed with nmap against the subnet.")
    hit = next(h for h in hits if h.keyword == "nmap")
    assert hit.technique_id is None
    assert hit.tactic == "Reconnaissance"


def test_attack_url_strips_subtechnique_suffix():
    assert attack_url("T1558.003") == "https://attack.mitre.org/techniques/T1558/"
