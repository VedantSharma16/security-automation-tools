import json

from secretscan.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main


def test_main_exits_clean_on_no_findings(tmp_path, capsys):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")

    exit_code = main([str(tmp_path), "--no-color"])

    assert exit_code == EXIT_CLEAN
    assert "No secrets detected" in capsys.readouterr().out


def test_main_exits_nonzero_on_findings(tmp_path, capsys):
    (tmp_path / "config.py").write_text('token = "ghp_' + "a" * 36 + '"\n')

    exit_code = main([str(tmp_path), "--no-color", "--no-entropy"])
    out = capsys.readouterr().out

    assert exit_code == EXIT_FINDINGS
    assert "github-pat" in out
    assert "ghp_" + "a" * 36 not in out  # raw secret never printed


def test_main_min_severity_filters_output(tmp_path, capsys):
    (tmp_path / "config.py").write_text('slack_hook = "hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx"\n')

    exit_code = main([str(tmp_path), "--no-color", "--no-entropy", "--min-severity", "critical"])

    assert exit_code == EXIT_CLEAN
    assert "No secrets detected" in capsys.readouterr().out


def test_main_writes_json_report(tmp_path):
    (tmp_path / "config.py").write_text('token = "ghp_' + "a" * 36 + '"\n')
    json_out = tmp_path / "report.json"

    main([str(tmp_path), "--no-color", "--no-entropy", "--json-out", str(json_out)])

    report = json.loads(json_out.read_text())
    assert report["finding_count"] == 1


def test_main_baseline_suppresses_previously_seen_finding(tmp_path):
    (tmp_path / "config.py").write_text('token = "ghp_' + "a" * 36 + '"\n')
    baseline_path = tmp_path / "baseline.json"

    first = main([str(tmp_path), "--no-color", "--no-entropy", "--baseline", str(baseline_path), "--update-baseline"])
    assert first == EXIT_FINDINGS
    assert baseline_path.exists()

    second = main([str(tmp_path), "--no-color", "--no-entropy", "--baseline", str(baseline_path)])
    assert second == EXIT_CLEAN


def test_main_invalid_rules_file_returns_error(tmp_path, capsys):
    bad_rules = tmp_path / "bad.yaml"
    bad_rules.write_text("not: a list\n")

    exit_code = main([str(tmp_path), "--rules", str(bad_rules)])

    assert exit_code == EXIT_ERROR
    assert "error" in capsys.readouterr().err
