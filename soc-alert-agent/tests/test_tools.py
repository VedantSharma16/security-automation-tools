from soc_agent.tools import TERMINAL_TOOLS, TOOL_SCHEMAS, ToolRegistry

SAMPLE_QUEUE = [
    {"alert_id": "A1", "src_ip": "1.2.3.4", "host": "web-prod-03", "user": "svc_web"},
    {"alert_id": "A2", "src_ip": "1.2.3.4", "host": "web-prod-03", "user": "svc_web"},
    {"alert_id": "A3", "src_ip": "9.9.9.9", "host": "printer-svc-09", "user": None},
]


def test_lookup_ioc_reputation_known_malicious():
    tools = ToolRegistry()
    result = tools.lookup_ioc_reputation("203.0.113.77")
    assert result["known_malicious"] is True
    assert result["confidence"] == "high"


def test_lookup_ioc_reputation_unknown_indicator():
    tools = ToolRegistry()
    result = tools.lookup_ioc_reputation("1.1.1.1")
    assert result["known_malicious"] is False
    assert result["confidence"] == "unknown"


def test_lookup_ioc_reputation_is_case_insensitive():
    tools = ToolRegistry()
    result = tools.lookup_ioc_reputation("EVIL-C2-PANEL.COM")
    assert result["known_malicious"] is True


def test_get_asset_criticality_known_host():
    tools = ToolRegistry()
    result = tools.get_asset_criticality("web-prod-03")
    assert result["criticality"] == "crown_jewel"


def test_get_asset_criticality_unknown_host():
    tools = ToolRegistry()
    result = tools.get_asset_criticality("some-unregistered-host")
    assert result["criticality"] == "unknown"


def test_search_attack_technique_matches_brute_force_language():
    tools = ToolRegistry()
    result = tools.search_attack_technique("Repeated failed login attempts followed by a successful login")
    ids = [m["id"] for m in result["matches"]]
    assert "T1110" in ids


def test_search_attack_technique_returns_no_matches_for_irrelevant_text():
    tools = ToolRegistry()
    result = tools.search_attack_technique("routine daily backup completed successfully")
    assert result["matches"] == []


def test_check_related_alerts_finds_shared_ip_and_host():
    tools = ToolRegistry(alerts=SAMPLE_QUEUE)
    result = tools.check_related_alerts("A1")
    assert result["count"] == 1
    assert result["related"][0]["alert_id"] == "A2"
    assert "src_ip" in result["related"][0]["shared_fields"]


def test_check_related_alerts_finds_none_for_isolated_alert():
    tools = ToolRegistry(alerts=SAMPLE_QUEUE)
    result = tools.check_related_alerts("A3")
    assert result["count"] == 0


def test_terminal_tools_return_verdict_and_reason():
    tools = ToolRegistry()
    for name in ("escalate", "monitor", "close"):
        result = tools.dispatch(name, {"reason": "test reason"})
        assert result == {"verdict": name, "reason": "test reason"}


def test_tool_schemas_cover_every_dispatchable_tool():
    schema_names = {s["name"] for s in TOOL_SCHEMAS}
    assert TERMINAL_TOOLS <= schema_names
    assert {"lookup_ioc_reputation", "get_asset_criticality", "search_attack_technique", "check_related_alerts"} <= schema_names


def test_dispatch_rejects_unknown_tool():
    tools = ToolRegistry()
    try:
        tools.dispatch("not_a_real_tool", {})
        assert False, "expected ValueError"
    except ValueError:
        pass
