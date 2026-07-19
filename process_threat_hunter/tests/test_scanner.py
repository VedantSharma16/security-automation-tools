import psutil

from hunter.rules import load_rules
from hunter.scanner import ProcessInfo, enumerate_processes, evaluate


def make_process(pid=1, name="bash", exe="/bin/bash", cmdline=None, username="alice"):
    return ProcessInfo(
        pid=pid,
        name=name,
        exe=exe,
        cmdline=cmdline or [exe],
        username=username,
        create_time=0.0,
    )


def make_rules(tmp_path, yaml_text):
    path = tmp_path / "rules.yaml"
    path.write_text(yaml_text)
    return load_rules(path)


def test_evaluate_flags_matching_process(tmp_path):
    rules = make_rules(
        tmp_path,
        "- id: mimikatz\n"
        "  pattern: 'mimikatz'\n"
        "  match_fields: [name, cmdline]\n"
        "  severity: critical\n"
        "  mitre_tactic: Credential Access\n"
        "  mitre_technique: T1003\n",
    )
    benign = make_process(pid=1, name="bash", cmdline=["/bin/bash"])
    malicious = make_process(pid=2, name="mimikatz.exe", cmdline=["mimikatz.exe", "privilege::debug"])

    findings = evaluate([benign, malicious], rules)

    assert len(findings) == 1
    assert findings[0].process.pid == 2
    assert findings[0].rule.id == "mimikatz"


def test_evaluate_matches_within_cmdline_arguments(tmp_path):
    rules = make_rules(
        tmp_path,
        "- id: encoded-ps\n"
        "  pattern: '-enc'\n"
        "  match_fields: [cmdline]\n"
        "  severity: high\n"
        "  mitre_tactic: Execution\n"
        "  mitre_technique: T1059.001\n",
    )
    proc = make_process(
        pid=3, name="powershell.exe", cmdline=["powershell.exe", "-enc", "SGVsbG8="]
    )

    findings = evaluate([proc], rules)

    assert len(findings) == 1
    assert findings[0].matched_field == "cmdline"


def test_evaluate_returns_empty_for_no_matches(tmp_path):
    rules = make_rules(
        tmp_path,
        "- id: mimikatz\n"
        "  pattern: 'mimikatz'\n"
        "  match_fields: [name]\n"
        "  severity: critical\n"
        "  mitre_tactic: Credential Access\n"
        "  mitre_technique: T1003\n",
    )
    findings = evaluate([make_process()], rules)
    assert findings == []


def test_process_fingerprint_is_pid_independent():
    p1 = make_process(pid=100, name="sshd", exe="/usr/sbin/sshd")
    p2 = make_process(pid=200, name="sshd", exe="/usr/sbin/sshd")
    assert p1.fingerprint() == p2.fingerprint()


def test_enumerate_processes_skips_processes_that_vanish(monkeypatch):
    # Simulates the real failure mode: a process exits between being listed
    # and being inspected, so accessing `.info` raises NoSuchProcess.
    class RaisingProcess:
        @property
        def info(self):
            raise psutil.NoSuchProcess(1)

    class OkProcess:
        info = {
            "pid": 2,
            "name": "init",
            "exe": "/sbin/init",
            "cmdline": ["/sbin/init"],
            "username": "root",
            "create_time": 0.0,
        }

    def fake_process_iter(attrs):
        return iter([RaisingProcess(), OkProcess()])

    monkeypatch.setattr(psutil, "process_iter", fake_process_iter)

    processes = enumerate_processes()

    assert len(processes) == 1
    assert processes[0].pid == 2
    assert processes[0].name == "init"
