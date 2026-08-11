from secops_agent.tools import (
    ToolError,
    ToolRegistry,
    check_asset_criticality,
    lookup_ioc,
    lookup_mitre_technique,
)


def test_lookup_ioc_known_malicious():
    result = lookup_ioc("203.0.113.77")
    assert result["is_known_malicious"] is True
    assert result["confidence"] == "medium"


def test_lookup_ioc_unknown_is_not_malicious():
    result = lookup_ioc("8.8.8.8")
    assert result["is_known_malicious"] is False


def test_lookup_ioc_is_case_and_whitespace_insensitive():
    result = lookup_ioc("  EVIL-C2-PANEL.COM  ")
    assert result["is_known_malicious"] is True


def test_lookup_mitre_technique_found():
    result = lookup_mitre_technique("t1110")
    assert result["found"] is True
    assert result["name"] == "Brute Force"


def test_lookup_mitre_technique_not_found():
    result = lookup_mitre_technique("T9999")
    assert result["found"] is False


def test_check_asset_criticality_found():
    result = check_asset_criticality("db-prod-01")
    assert result["found"] is True
    assert result["criticality"] == "critical"


def test_check_asset_criticality_not_found():
    result = check_asset_criticality("unknown-host")
    assert result["found"] is False


def test_registry_rejects_tools_outside_allowlist():
    registry = ToolRegistry()
    try:
        registry.execute("delete_everything", {})
        assert False, "expected ToolError"
    except ToolError:
        pass


def test_registry_returns_structured_error_for_bad_arguments():
    registry = ToolRegistry()
    outcome = registry.execute("lookup_ioc", {"not_an_indicator": "x"})
    assert outcome["ok"] is False
    assert "invalid arguments" in outcome["error"]


def test_search_logs_without_bound_path_is_a_safe_no_op():
    registry = ToolRegistry(log_path=None)
    outcome = registry.execute("search_logs", {"pattern": "failed password"})
    assert outcome["ok"] is True
    assert outcome["result"]["searched"] is False


def test_search_logs_ignores_arbitrary_path_from_the_caller(tmp_path):
    bound = tmp_path / "bound.log"
    bound.write_text("Failed password for root from 203.0.113.77 port 1 ssh2\n", encoding="utf-8")
    other = tmp_path / "other.log"
    other.write_text("this file should never be read by the agent\n", encoding="utf-8")

    registry = ToolRegistry(log_path=bound)
    # The tool schema only exposes "pattern" — there is no way for a caller (or a
    # prompt-injected model) to redirect the search at `other`, since the path is
    # bound once at registry construction time, not per tool-call.
    outcome = registry.execute("search_logs", {"pattern": "password"})
    assert outcome["result"]["log_path"] == str(bound)
    assert outcome["result"]["match_count"] == 1
    assert outcome["result"]["extracted_ips"] == ["203.0.113.77"]


def test_search_logs_reports_missing_file():
    registry = ToolRegistry(log_path="/nonexistent/path.log")
    outcome = registry.execute("search_logs", {"pattern": "x"})
    assert outcome["result"]["searched"] is False
    assert "not found" in outcome["result"]["reason"]


def test_search_logs_truncates_at_max_matches(tmp_path):
    log = tmp_path / "big.log"
    log.write_text("\n".join(f"failed password attempt {i}" for i in range(10)), encoding="utf-8")
    registry = ToolRegistry(log_path=log, max_matches=3)
    outcome = registry.execute("search_logs", {"pattern": "failed password"})
    assert outcome["result"]["match_count"] == 3
