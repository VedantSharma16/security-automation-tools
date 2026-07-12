import psutil

from hunter.cli import EXIT_CLEAN, EXIT_FINDINGS, main


class FakeProc:
    def __init__(self, pid, name, exe, cmdline):
        self.info = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "cmdline": cmdline,
            "username": "alice",
            "create_time": 0.0,
        }


def test_main_exits_clean_when_no_findings(tmp_path, monkeypatch, capsys):
    def fake_process_iter(attrs):
        return iter([FakeProc(1, "bash", "/bin/bash", ["/bin/bash"])])

    monkeypatch.setattr(psutil, "process_iter", fake_process_iter)

    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "- id: mimikatz\n"
        "  pattern: 'mimikatz'\n"
        "  match_fields: [name]\n"
        "  severity: critical\n"
        "  mitre_tactic: Credential Access\n"
        "  mitre_technique: T1003\n"
    )

    exit_code = main(["--rules", str(rules_path)])

    assert exit_code == EXIT_CLEAN
    assert "No rule matches" in capsys.readouterr().out


def test_main_exits_nonzero_when_findings_present(tmp_path, monkeypatch, capsys):
    def fake_process_iter(attrs):
        return iter([FakeProc(2, "mimikatz.exe", "C:/tools/mimikatz.exe", ["mimikatz.exe"])])

    monkeypatch.setattr(psutil, "process_iter", fake_process_iter)

    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "- id: mimikatz\n"
        "  pattern: 'mimikatz'\n"
        "  match_fields: [name]\n"
        "  severity: critical\n"
        "  mitre_tactic: Credential Access\n"
        "  mitre_technique: T1003\n"
    )

    exit_code = main(["--rules", str(rules_path), "--no-color"])

    assert exit_code == EXIT_FINDINGS
    assert "mimikatz" in capsys.readouterr().out


def test_main_writes_json_report(tmp_path, monkeypatch):
    def fake_process_iter(attrs):
        return iter([FakeProc(1, "bash", "/bin/bash", ["/bin/bash"])])

    monkeypatch.setattr(psutil, "process_iter", fake_process_iter)

    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "- id: mimikatz\n"
        "  pattern: 'mimikatz'\n"
        "  match_fields: [name]\n"
        "  severity: critical\n"
        "  mitre_tactic: Credential Access\n"
        "  mitre_technique: T1003\n"
    )
    json_out = tmp_path / "report.json"

    main(["--rules", str(rules_path), "--json-out", str(json_out)])

    assert json_out.exists()


def test_main_update_baseline_then_detects_new_process(tmp_path, monkeypatch):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "- id: mimikatz\n"
        "  pattern: 'mimikatz'\n"
        "  match_fields: [name]\n"
        "  severity: critical\n"
        "  mitre_tactic: Credential Access\n"
        "  mitre_technique: T1003\n"
    )
    baseline_path = tmp_path / "baseline.json"

    monkeypatch.setattr(
        psutil, "process_iter",
        lambda attrs: iter([FakeProc(1, "bash", "/bin/bash", ["/bin/bash"])]),
    )
    main(["--rules", str(rules_path), "--baseline", str(baseline_path), "--update-baseline"])
    assert baseline_path.exists()

    monkeypatch.setattr(
        psutil, "process_iter",
        lambda attrs: iter([
            FakeProc(1, "bash", "/bin/bash", ["/bin/bash"]),
            FakeProc(2, "newthing", "/opt/newthing", ["/opt/newthing"]),
        ]),
    )
    report = None
    import hunter.cli as cli_mod

    original_build_report = cli_mod.report_mod.build_report

    def capture(*args, **kwargs):
        nonlocal report
        report = original_build_report(*args, **kwargs)
        return report

    monkeypatch.setattr(cli_mod.report_mod, "build_report", capture)

    main(["--rules", str(rules_path), "--baseline", str(baseline_path)])

    assert report is not None
    assert len(report["new_since_baseline"]) == 1
    assert report["new_since_baseline"][0]["name"] == "newthing"
