from soc_agent.tools import (
    ToolContext,
    check_ioc_reputation,
    check_process_baseline,
    finish_investigation,
    lookup_attack_technique,
    search_logs,
)

def _ctx(log_path=None):
    return ToolContext.load_default(log_path=log_path)


def test_load_default_populates_all_data_sources():
    ctx = _ctx()
    assert "203.0.113.77" in ctx.threat_intel
    assert any(t["id"] == "T1110" for t in ctx.attack_techniques)
    assert "sshd" in ctx.process_baseline


def test_check_ioc_reputation_known_malicious():
    ctx = _ctx()
    result = check_ioc_reputation(ctx, indicator="203.0.113.77")
    assert result["known_malicious"] is True
    assert result["source"] == "demo-feed"


def test_check_ioc_reputation_unknown_indicator():
    ctx = _ctx()
    result = check_ioc_reputation(ctx, indicator="198.51.100.20")
    assert result["known_malicious"] is False
    assert "No match" in result["notes"]


def test_check_ioc_reputation_is_case_insensitive():
    ctx = _ctx()
    result = check_ioc_reputation(ctx, indicator="EVIL-C2-RELAY.NET")
    assert result["known_malicious"] is True


def test_search_logs_without_log_path_returns_empty():
    ctx = _ctx(log_path=None)
    result = search_logs(ctx, query="203.0.113.77")
    assert result["matched_lines"] == []
    assert "No log file" in result["note"]


def test_search_logs_finds_matching_lines(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Sep 9 03:11:02 host sshd: Failed password for admin from 203.0.113.77\n"
        "Sep 9 03:12:20 host sshd: Accepted password for admin from 203.0.113.77\n"
        "Sep 9 03:13:00 host sshd: Failed password for root from 198.51.100.9\n"
    )
    ctx = _ctx(log_path=log_file)
    result = search_logs(ctx, query="203.0.113.77")
    assert result["total_matches"] == 2
    assert all("203.0.113.77" in line for line in result["matched_lines"])


def test_search_logs_respects_max_lines(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("\n".join(f"hit {i} 1.2.3.4" for i in range(30)))
    ctx = _ctx(log_path=log_file)
    result = search_logs(ctx, query="1.2.3.4", max_lines=5)
    assert result["total_matches"] == 30
    assert len(result["matched_lines"]) == 5


def test_lookup_attack_technique_matches_brute_force_keywords():
    ctx = _ctx()
    result = lookup_attack_technique(ctx, keywords="repeated failed password attempts, brute force guessing")
    ids = [m["id"] for m in result["matches"]]
    assert "T1110" in ids


def test_lookup_attack_technique_returns_empty_for_irrelevant_text():
    ctx = _ctx()
    result = lookup_attack_technique(ctx, keywords="quarterly budget spreadsheet review meeting")
    assert result["matches"] == []


def test_check_process_baseline_known_good():
    ctx = _ctx()
    result = check_process_baseline(ctx, process_name="sshd")
    assert result["known_good"] is True


def test_check_process_baseline_unknown_process():
    ctx = _ctx()
    result = check_process_baseline(ctx, process_name="mimikatz.exe")
    assert result["known_good"] is False
    assert "verify legitimacy" in result["notes"]


def test_finish_investigation_returns_structured_dict():
    ctx = _ctx()
    result = finish_investigation(
        ctx,
        severity="high",
        summary="Test summary.",
        key_indicators=["1.2.3.4"],
        matched_techniques=["T1110 Brute Force"],
        recommended_actions=["Do the thing."],
    )
    assert result["severity"] == "high"
    assert result["key_indicators"] == ["1.2.3.4"]


def test_finish_investigation_rejects_invalid_severity():
    ctx = _ctx()
    import pytest

    with pytest.raises(ValueError):
        finish_investigation(
            ctx,
            severity="apocalyptic",
            summary="x",
            key_indicators=[],
            matched_techniques=[],
            recommended_actions=[],
        )
