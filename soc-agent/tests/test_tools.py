from soc_agent import tools


def test_lookup_asset_criticality_known_crown_jewel():
    result = tools.lookup_asset_criticality("db-primary.prod.internal")
    assert result["known_asset"] is True
    assert result["criticality"] == "crown_jewel"
    assert result["owner"] == "data-team"


def test_lookup_asset_criticality_unknown_host():
    result = tools.lookup_asset_criticality("mystery-box")
    assert result["known_asset"] is False
    assert result["criticality"] == "unknown"


def test_lookup_ioc_reputation_malicious():
    result = tools.lookup_ioc_reputation("203.0.113.55")
    assert result["known"] is True
    assert result["verdict"] == "malicious"


def test_lookup_ioc_reputation_unknown_indicator():
    result = tools.lookup_ioc_reputation("1.2.3.4")
    assert result["known"] is False
    assert result["verdict"] == "unknown"


def test_lookup_user_risk_anomalous_user():
    result = tools.lookup_user_risk("svc_backup")
    assert result["known_user"] is True
    assert result["anomalous"] is True
    assert result["failed_logins_24h"] == 12


def test_lookup_user_risk_unknown_user():
    result = tools.lookup_user_risk("ghost")
    assert result["known_user"] is False
    assert result["anomalous"] is False


def test_check_process_baseline_flags_unbaselined_process():
    result = tools.check_process_baseline("db-primary.prod.internal", "powershell.exe")
    assert result["host_has_baseline"] is True
    assert result["is_baselined"] is False


def test_check_process_baseline_accepts_known_process():
    result = tools.check_process_baseline("ws-jsmith", "chrome.exe")
    assert result["host_has_baseline"] is True
    assert result["is_baselined"] is True


def test_check_process_baseline_unknown_host():
    result = tools.check_process_baseline("unmanaged-host", "cmd.exe")
    assert result["host_has_baseline"] is False
    assert result["is_baselined"] is None


def test_tool_schemas_and_implementations_are_consistent():
    schema_names = {schema["name"] for schema in tools.TOOL_SCHEMAS}
    impl_names = set(tools.TOOL_IMPLEMENTATIONS.keys())
    assert schema_names == impl_names


def test_tool_implementations_dispatch_correctly():
    result = tools.TOOL_IMPLEMENTATIONS["lookup_ioc_reputation"]({"indicator": "203.0.113.55"})
    assert result["verdict"] == "malicious"
