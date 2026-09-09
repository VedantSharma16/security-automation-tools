from pathlib import Path

from soc_agent.offline_planner import run_offline_investigation
from soc_agent.tools import ToolContext

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _read(name: str) -> str:
    return (EXAMPLES_DIR / name).read_text(encoding="utf-8")


def test_brute_force_compromise_alert_scores_critical_with_logs():
    alert = _read("alert_bruteforce_compromise.txt")
    ctx = ToolContext.load_default(log_path=EXAMPLES_DIR / "sample_auth.log")

    verdict, transcript = run_offline_investigation(alert, ctx)

    assert verdict.severity == "critical"
    assert "203.0.113.77" in verdict.key_indicators
    assert "admin" in verdict.key_indicators
    assert any("T1110" in t for t in verdict.matched_techniques)
    assert verdict.steps_taken == len(transcript)
    assert any(step.tool == "finish_investigation" for step in transcript)


def test_brute_force_alert_without_logs_is_still_high_from_reputation_hit():
    alert = _read("alert_bruteforce_compromise.txt")
    ctx = ToolContext.load_default(log_path=None)

    verdict, _ = run_offline_investigation(alert, ctx)

    # No log file provided, so no brute-force *pattern* is confirmed, but the
    # source IP alone is still known-malicious, which should never be silently
    # downgraded to a "no evidence" verdict.
    assert verdict.severity in ("high", "critical")


def test_benign_alert_scores_low():
    alert = _read("alert_benign_login.txt")
    ctx = ToolContext.load_default(log_path=None)

    verdict, transcript = run_offline_investigation(alert, ctx)

    assert verdict.severity == "low"
    assert verdict.recommended_actions == ["No immediate action required; log the alert as reviewed and closed."]
    assert any(step.tool == "check_ioc_reputation" for step in transcript)


def test_transcript_calls_are_recorded_in_order_ending_with_finish():
    alert = _read("alert_bruteforce_compromise.txt")
    ctx = ToolContext.load_default(log_path=EXAMPLES_DIR / "sample_auth.log")

    _, transcript = run_offline_investigation(alert, ctx)

    assert transcript[-1].tool == "finish_investigation"
    tool_names = {step.tool for step in transcript}
    assert "check_ioc_reputation" in tool_names
    assert "search_logs" in tool_names
    assert "lookup_attack_technique" in tool_names


def test_critical_severity_recommends_isolation_and_blocking():
    alert = _read("alert_bruteforce_compromise.txt")
    ctx = ToolContext.load_default(log_path=EXAMPLES_DIR / "sample_auth.log")

    verdict, _ = run_offline_investigation(alert, ctx)

    joined = " ".join(verdict.recommended_actions)
    assert "Isolate" in joined
    assert "203.0.113.77" in joined
    assert "admin" in joined
