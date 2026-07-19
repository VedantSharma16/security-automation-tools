from hunter.baseline import diff_baseline, load_baseline, save_baseline
from hunter.scanner import ProcessInfo


def make_process(pid, name, exe):
    return ProcessInfo(pid=pid, name=name, exe=exe, cmdline=[exe], username="alice", create_time=0.0)


def test_save_and_load_baseline_round_trip(tmp_path):
    path = tmp_path / "baseline.json"
    processes = [make_process(1, "sshd", "/usr/sbin/sshd"), make_process(2, "bash", "/bin/bash")]

    save_baseline(processes, path)
    loaded = load_baseline(path)

    assert loaded == {"sshd:/usr/sbin/sshd", "bash:/bin/bash"}


def test_diff_baseline_flags_only_new_processes(tmp_path):
    path = tmp_path / "baseline.json"
    known = [make_process(1, "sshd", "/usr/sbin/sshd")]
    save_baseline(known, path)
    baseline = load_baseline(path)

    current = [
        make_process(1, "sshd", "/usr/sbin/sshd"),
        make_process(99, "mimikatz.exe", "C:/tools/mimikatz.exe"),
    ]

    new = diff_baseline(current, baseline)

    assert len(new) == 1
    assert new[0].name == "mimikatz.exe"


def test_diff_baseline_ignores_pid_changes():
    """A restarted, legitimate process shouldn't be flagged as new."""
    baseline = {"sshd:/usr/sbin/sshd"}
    current = [make_process(pid=54321, name="sshd", exe="/usr/sbin/sshd")]

    assert diff_baseline(current, baseline) == []
