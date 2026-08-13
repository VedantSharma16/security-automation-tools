from recon_agent.agent import DeterministicPlanner, RunState, run
from recon_agent.vuln_kb import VulnKnowledgeBase


def fake_scan(host, ports=None):
    return {"host": host, "ports_scanned": ports or [], "open_ports": [22, 443]}


def fake_banner(host, port):
    assert port == 22
    return {"host": host, "port": port, "banner": "SSH-2.0-OpenSSH_7.2", "service": "OpenSSH", "version": "7.2", "error": None}


def fake_http_headers(host, port, use_tls=False):
    assert port == 443
    assert use_tls is True
    return {
        "host": host, "port": port, "status_line": "HTTP/1.1 200 OK", "headers": {"Server": "nginx/1.4.0"},
        "server": "nginx/1.4.0", "service": "nginx", "version": "1.4.0", "error": None,
    }


def fake_tls_cert_info(host, port):
    assert port == 443
    return {
        "host": host, "port": port, "protocol": "TLSv1.2", "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "subject": "CN=127.0.0.1", "issuer": "CN=127.0.0.1", "not_after": "2099-01-01T00:00:00+00:00",
        "days_until_expiry": 9000, "error": None,
    }


FAKE_TOOLS = {
    "tcp_connect_scan": fake_scan,
    "grab_banner": fake_banner,
    "http_headers": fake_http_headers,
    "tls_cert_info": fake_tls_cert_info,
}


def test_deterministic_planner_scans_first():
    planner = DeterministicPlanner()
    action = planner.next_action(RunState(target="test.local"))
    assert action.tool == "tcp_connect_scan"


def test_deterministic_planner_returns_none_when_nothing_left():
    state = RunState(target="test.local", scanned=True, open_ports=[])
    assert DeterministicPlanner().next_action(state) is None


def test_full_run_discovers_ports_fingerprints_and_vulns():
    result = run("test.local", planner=DeterministicPlanner(), kb=VulnKnowledgeBase(), tool_overrides=FAKE_TOOLS)

    assert result.completed is True
    assert result.open_ports == [22, 443]
    assert result.fingerprints[22] == {"service": "OpenSSH", "version": "7.2", "source": "banner"}
    assert result.fingerprints[443] == {"service": "nginx", "version": "1.4.0", "source": "http"}
    assert 443 in result.tls_info

    cves = {m.cve for m in result.vuln_matches}
    assert "CVE-2016-6210" in cves  # OpenSSH 7.2
    assert "CVE-2013-2028" in cves  # nginx 1.4.0
    assert result.risk == "high"    # highest severity present across matches
    assert result.steps_taken == 6  # scan, 2x fingerprint, tls, 2x vuln_lookup


def test_run_respects_max_steps_budget():
    result = run("test.local", planner=DeterministicPlanner(), kb=VulnKnowledgeBase(),
                 tool_overrides=FAKE_TOOLS, max_steps=1)
    assert result.steps_taken == 1
    assert result.completed is False


def test_run_with_no_open_ports_has_low_risk_none():
    result = run(
        "test.local",
        planner=DeterministicPlanner(),
        kb=VulnKnowledgeBase(),
        tool_overrides={"tcp_connect_scan": lambda host, ports=None: {"host": host, "ports_scanned": [], "open_ports": []}},
    )
    assert result.open_ports == []
    assert result.vuln_matches == []
    assert result.risk == "none"
    assert result.completed is True


def test_agent_run_result_to_dict_is_json_serializable():
    import json

    result = run("test.local", planner=DeterministicPlanner(), kb=VulnKnowledgeBase(), tool_overrides=FAKE_TOOLS)
    serialized = json.dumps(result.to_dict())
    assert "CVE-2016-6210" in serialized
