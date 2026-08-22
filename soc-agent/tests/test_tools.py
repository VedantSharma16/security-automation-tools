from soc_agent.tools import (
    ToolRegistry,
    asset_criticality_lookup,
    attack_technique_lookup,
    process_reputation_lookup,
    threat_intel_lookup,
    user_baseline_check,
)

FEED = {"1.2.3.4": {"confidence": "high", "source": "test-feed", "notes": "test hit"}}
INVENTORY = {"DC01": {"criticality": "critical", "owner": "IT", "environment": "production"}}
BASELINES = {"jsmith": ["WKS-01"]}
TECHNIQUES = [
    {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "keywords": ["powershell", "encoded"], "text": "..."},
    {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access", "keywords": ["mimikatz"], "text": "..."},
]


def test_threat_intel_lookup_hit():
    result = threat_intel_lookup("1.2.3.4", FEED)
    assert result["is_malicious"] is True
    assert result["confidence"] == "high"


def test_threat_intel_lookup_miss():
    result = threat_intel_lookup("8.8.8.8", FEED)
    assert result["is_malicious"] is False
    assert result["confidence"] == "none"


def test_process_reputation_flags_encoded_powershell():
    result = process_reputation_lookup("powershell.exe", "powershell.exe -enc SQBuAHYAbwBrAGUA")
    assert result["is_suspicious"] is True
    assert any("Base64" in note for note in result["matched_patterns"])


def test_process_reputation_flags_mimikatz():
    result = process_reputation_lookup("cmd.exe", "cmd.exe /c mimikatz.exe privilege::debug")
    assert result["is_suspicious"] is True
    assert any("Mimikatz" in note for note in result["matched_patterns"])


def test_process_reputation_clean_process():
    result = process_reputation_lookup("outlook.exe", "outlook.exe")
    assert result["is_suspicious"] is False
    assert result["matched_patterns"] == []


def test_asset_criticality_lookup_known_and_unknown():
    known = asset_criticality_lookup("DC01", INVENTORY)
    assert known["known_asset"] is True
    assert known["criticality"] == "critical"

    unknown = asset_criticality_lookup("WKS-9999", INVENTORY)
    assert unknown["known_asset"] is False
    assert unknown["criticality"] == "unknown"

    none_host = asset_criticality_lookup(None, INVENTORY)
    assert none_host["known_asset"] is False


def test_user_baseline_check_deviation_and_match():
    deviation = user_baseline_check("jsmith", "DC01", BASELINES)
    assert deviation["baseline_known"] is True
    assert deviation["is_deviation"] is True

    normal = user_baseline_check("jsmith", "WKS-01", BASELINES)
    assert normal["is_deviation"] is False

    unknown_user = user_baseline_check("nobody", "DC01", BASELINES)
    assert unknown_user["baseline_known"] is False
    assert unknown_user["is_deviation"] is False


def test_attack_technique_lookup_matches_keywords():
    result = attack_technique_lookup(["Base64-encoded PowerShell command"], TECHNIQUES)
    ids = [t["id"] for t in result["matches"]]
    assert "T1059.001" in ids
    assert "T1003" not in ids


def test_attack_technique_lookup_no_matches():
    result = attack_technique_lookup(["nothing interesting here"], TECHNIQUES)
    assert result["matches"] == []


def test_registry_call_dispatches_to_correct_tool():
    registry = ToolRegistry(
        threat_intel=FEED, asset_inventory=INVENTORY, user_baselines=BASELINES, attack_techniques=TECHNIQUES
    )
    result = registry.call("threat_intel_lookup", {"indicator": "1.2.3.4"})
    assert result["is_malicious"] is True


def test_registry_call_unknown_tool_raises():
    registry = ToolRegistry()
    try:
        registry.call("does_not_exist", {})
        assert False, "expected KeyError"
    except KeyError:
        pass


def test_registry_specs_have_expected_tools():
    registry = ToolRegistry()
    names = {spec.name for spec in registry.specs()}
    assert names == {
        "threat_intel_lookup",
        "process_reputation_lookup",
        "asset_criticality_lookup",
        "user_baseline_check",
        "attack_technique_lookup",
    }
