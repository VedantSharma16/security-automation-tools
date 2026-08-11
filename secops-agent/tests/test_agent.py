from secops_agent.agent import SecOpsAgent
from secops_agent.planner import OfflinePlanner
from secops_agent.tools import ToolRegistry

SAMPLE_LOG = (
    "Jan 15 03:22:01 db-prod-01 sshd[1]: Failed password for invalid user admin "
    "from 203.0.113.77 port 51515 ssh2\n"
    "Jan 15 03:22:45 db-prod-01 sshd[1]: Accepted password for root from "
    "203.0.113.77 port 51530 ssh2\n"
)


def _agent(log_path=None, max_iterations=8):
    return SecOpsAgent(planner=OfflinePlanner(), tools=ToolRegistry(log_path=log_path), max_iterations=max_iterations)


def test_full_investigation_flags_malicious_ip_on_critical_asset(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(SAMPLE_LOG, encoding="utf-8")

    agent = _agent(log_path=log)
    investigation = agent.investigate(
        "Investigate repeated failed logins on db-prod-01 from 203.0.113.77 (technique T1110?)"
    )

    tool_order = [r.tool for r in investigation.trace]
    assert tool_order[0] == "search_logs"
    assert "lookup_ioc" in tool_order
    assert "check_asset_criticality" in tool_order
    assert "lookup_mitre_technique" in tool_order

    ioc_record = next(r for r in investigation.trace if r.tool == "lookup_ioc")
    assert ioc_record.output["is_known_malicious"] is True

    asset_record = next(r for r in investigation.trace if r.tool == "check_asset_criticality")
    assert asset_record.output["criticality"] == "critical"

    assert investigation.verdict == "malicious (critical asset in scope)"
    assert investigation.stopped_early is False
    assert "KNOWN MALICIOUS" in investigation.final_report


def test_investigation_with_no_entities_and_no_log_is_inconclusive_not_crashing():
    agent = _agent(log_path=None)
    investigation = agent.investigate("Is anything suspicious going on right now?")

    assert investigation.trace[0].tool == "search_logs"
    assert investigation.trace[0].output["searched"] is False
    assert investigation.verdict == "no evidence gathered"
    assert investigation.stopped_early is False


def test_clean_ip_yields_inconclusive_not_malicious(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Jan 15 09:10:12 db-prod-01 sshd[1]: Accepted publickey for deploy "
        "from 198.51.100.20 port 60122 ssh2\n",
        encoding="utf-8",
    )
    agent = _agent(log_path=log)
    investigation = agent.investigate("Check login from 198.51.100.20 on db-prod-01")

    assert investigation.verdict == "suspicious (critical asset in scope, no confirmed-malicious IOC)"
    assert investigation.final_report


def test_iteration_budget_stops_the_agent_before_a_final_answer(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(SAMPLE_LOG, encoding="utf-8")

    agent = _agent(log_path=log, max_iterations=1)
    investigation = agent.investigate("Investigate 203.0.113.77 on db-prod-01, technique T1110")

    assert investigation.stopped_early is True
    assert len(investigation.trace) == 1
    assert "budget" in investigation.final_report
