import json
from pathlib import Path

from sigma_tuner.cli import EXIT_CONVERGED, EXIT_ERROR, EXIT_NOT_CONVERGED, main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_list_techniques(capsys):
    exit_code = main(["list-techniques"])

    out = capsys.readouterr().out
    assert exit_code == EXIT_CONVERGED
    assert "T1110" in out
    assert "T1003.001" in out


def test_tune_json_to_stdout(capsys):
    exit_code = main(
        ["tune", "--technique", "T1110", "--events", str(EXAMPLES / "t1110_ssh_bruteforce.jsonl"), "--format", "json"]
    )

    out = capsys.readouterr().out
    report = json.loads(out)

    assert exit_code == EXIT_CONVERGED
    assert report["converged"] is True
    assert report["selected_variant"] == "v5_lower_threshold_2"
    assert "final_rule" in report
    assert "narrative" in report


def test_tune_writes_to_out_file(tmp_path):
    out_path = tmp_path / "report.json"

    exit_code = main(
        [
            "tune",
            "--technique",
            "T1003.001",
            "--events",
            str(EXAMPLES / "t1003.001_credential_dumping.jsonl"),
            "--format",
            "json",
            "--out",
            str(out_path),
        ]
    )

    assert exit_code == EXIT_CONVERGED
    report = json.loads(out_path.read_text())
    assert report["selected_variant"] == "v2_known_techniques"


def test_tune_exits_nonzero_when_thresholds_too_strict(capsys):
    exit_code = main(
        [
            "tune",
            "--technique",
            "T1110",
            "--events",
            str(EXAMPLES / "t1110_ssh_bruteforce.jsonl"),
            "--precision-threshold",
            "1.0",
            "--recall-threshold",
            "0.99",
        ]
    )

    assert exit_code == EXIT_NOT_CONVERGED


def test_tune_markdown_format(capsys):
    exit_code = main(
        [
            "tune",
            "--technique",
            "T1110",
            "--events",
            str(EXAMPLES / "t1110_ssh_bruteforce.jsonl"),
            "--format",
            "markdown",
        ]
    )
    out = capsys.readouterr().out
    assert exit_code == EXIT_CONVERGED
    assert out.startswith("# Sigma rule tuning report")
    assert "| Variant | Precision | Recall | F1 | Rationale |" in out


def test_tune_yaml_format_emits_final_rule_only(capsys):
    main(
        ["tune", "--technique", "T1003.001", "--events", str(EXAMPLES / "t1003.001_credential_dumping.jsonl"), "--format", "yaml"]
    )
    out = capsys.readouterr().out
    assert "detection:" in out
    assert "condition:" in out
    assert "narrative" not in out


def test_unknown_technique_exits_with_error(capsys):
    exit_code = main(["tune", "--technique", "T9999", "--events", str(EXAMPLES / "t1110_ssh_bruteforce.jsonl")])

    assert exit_code == EXIT_ERROR
    assert "unknown technique" in capsys.readouterr().err


def test_missing_events_file_exits_with_error(capsys):
    exit_code = main(["tune", "--technique", "T1110", "--events", "/no/such/file.jsonl"])

    assert exit_code == EXIT_ERROR
