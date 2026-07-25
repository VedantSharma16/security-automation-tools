from agentic_soc.tools import ToolRegistry


def test_lookup_ioc_matches_known_indicator():
    registry = ToolRegistry.from_files()
    result = registry.lookup_ioc("91.203.145.12")
    assert result["matched"] is True
    assert result["confidence"] == "high"


def test_lookup_ioc_case_insensitive_and_unmatched():
    registry = ToolRegistry.from_files()
    assert registry.lookup_ioc("SECURE-BILLING-PORTAL.NET")["matched"] is True
    result = registry.lookup_ioc("8.8.8.8")
    assert result["matched"] is False
    assert "No match" in result["notes"]


def test_check_process_flags_known_lolbin():
    registry = ToolRegistry.from_files()
    result = registry.check_process("powershell.exe")
    assert result["known_lolbin"] is True
    assert result["risk_level"] == "high"
    assert result["technique_id"] == "T1059.001"


def test_check_process_unknown_binary():
    registry = ToolRegistry.from_files()
    result = registry.check_process("notepad.exe")
    assert result["known_lolbin"] is False


def test_lookup_attack_technique_returns_relevant_match():
    registry = ToolRegistry.from_files()
    result = registry.lookup_attack_technique("scheduled task persistence via schtasks", top_k=2)
    assert result["matches"]
    assert result["matches"][0]["id"] == "T1053.005"


def test_lookup_attack_technique_no_match_returns_empty_list():
    registry = ToolRegistry.from_files()
    result = registry.lookup_attack_technique("zzz qqq nonsense unrelated words", top_k=2)
    assert result["matches"] == []


def test_get_asset_criticality_known_and_unknown_host():
    registry = ToolRegistry.from_files()
    known = registry.get_asset_criticality("DC-PRIMARY-01")
    assert known["known_asset"] is True
    assert known["criticality"] == "critical"

    unknown = registry.get_asset_criticality("SOME-RANDOM-HOST")
    assert unknown["known_asset"] is False
    assert unknown["criticality"] == "unknown"


def test_tools_expose_anthropic_compatible_schema():
    registry = ToolRegistry.from_files()
    schemas = [t.anthropic_schema() for t in registry.tools()]
    names = {s["name"] for s in schemas}
    assert names == {"lookup_ioc", "check_process", "lookup_attack_technique", "get_asset_criticality"}
    for schema in schemas:
        assert "input_schema" in schema
        assert schema["input_schema"]["type"] == "object"
