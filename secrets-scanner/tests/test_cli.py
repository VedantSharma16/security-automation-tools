import json
import subprocess

from secretscanner.cli import build_arg_parser, main


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def test_arg_parser_defaults():
    parser = build_arg_parser()
    args = parser.parse_args(["/some/path"])
    assert args.path == "/some/path"
    assert args.history is False
    assert args.format == "markdown"
    assert args.min_severity == "low"


def test_main_returns_1_for_missing_path(capsys):
    exit_code = main(["/does/not/exist"])
    assert exit_code == 1
    assert "no such path" in capsys.readouterr().err


def test_main_finds_secret_and_returns_2(tmp_path, capsys):
    (tmp_path / "config.py").write_text("AWS_KEY = 'AKIAZQTKPMNBVCXWERTY'\n")

    exit_code = main([str(tmp_path), "--format", "json"])

    assert exit_code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["likely_genuine"] == 1


def test_main_returns_0_for_clean_directory(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")
    assert main([str(tmp_path)]) == 0


def test_main_writes_to_file_when_out_given(tmp_path):
    (tmp_path / "clean.py").write_text("x = 1\n")
    out_file = tmp_path / "report.md"

    exit_code = main([str(tmp_path), "--out", str(out_file)])

    assert exit_code == 0
    assert out_file.exists()
    assert "Secret Scan Report" in out_file.read_text()


def test_main_min_severity_filters_low_findings(tmp_path):
    # A generic-secret match is "medium" severity; --min-severity high should drop it.
    (tmp_path / "config.py").write_text("api_key = 'sup3r-s3cr3t-v4lue-z9q7m2x8'\n")
    assert main([str(tmp_path), "--min-severity", "high"]) == 0
    assert main([str(tmp_path), "--min-severity", "low"]) == 2


def test_main_history_flag_scans_git_log(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "dev@example.com")
    _git(repo, "config", "user.name", "Dev")

    secret_file = repo / "config.py"
    secret_file.write_text("AWS_KEY = 'AKIAZQTKPMNBVCXWERTY'\n")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "add secret")

    secret_file.write_text("AWS_KEY = os.environ['AWS_KEY']\n")
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "remove secret")

    exit_code = main([str(repo), "--history", "--format", "json"])

    assert exit_code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["git_history_findings"] == 1
    assert report["summary"]["working_tree_findings"] == 0


def test_main_history_only_errors_on_non_git_dir(tmp_path, capsys):
    exit_code = main([str(tmp_path), "--history-only"])
    assert exit_code == 1
    assert "not a git repository" in capsys.readouterr().err
