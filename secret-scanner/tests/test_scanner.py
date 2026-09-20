import subprocess
from pathlib import Path

from secret_fixtures import build_dirty_file_text, fake_aws_access_key_id, fake_github_pat
from secret_scanner.scanner import (
    Finding,
    is_probably_binary,
    iter_scannable_files,
    redact,
    scan_file_content,
    scan_git_history,
    scan_paths,
)

FIXTURES = Path(__file__).parent / "fixtures"
AWS_KEY = fake_aws_access_key_id()


def _run_git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def _init_git_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.email", "test@example.com")
    _run_git(repo, "config", "user.name", "Test User")


class TestRedact:
    def test_redact_keeps_first_and_last_four_characters(self):
        assert redact(AWS_KEY) == AWS_KEY[:4] + "*" * (len(AWS_KEY) - 8) + AWS_KEY[-4:]

    def test_redact_fully_masks_short_values(self):
        assert redact("abcd1234") == "********"


class TestFindingProperties:
    def test_redacted_secret_matches_redact_function(self):
        finding = Finding(
            rule_id="aws-access-key-id",
            description="AWS Access Key ID",
            severity="critical",
            file_path="app.py",
            line_number=3,
            secret=AWS_KEY,
            line_text=f'key = "{AWS_KEY}"',
        )
        assert finding.redacted_secret == redact(AWS_KEY)
        assert finding.secret not in finding.redacted_line
        assert AWS_KEY[:4] in finding.redacted_line  # prefix still visible for triage

    def test_fingerprint_is_stable_and_ignores_line_number(self):
        base = dict(
            rule_id="github-pat",
            description="GitHub PAT",
            severity="critical",
            file_path="app.py",
            secret=fake_github_pat(),
            line_text="token",
        )
        f1 = Finding(line_number=10, **base)
        f2 = Finding(line_number=99, **base)
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_differs_for_different_secrets(self):
        base = dict(
            rule_id="github-pat",
            description="GitHub PAT",
            severity="critical",
            file_path="app.py",
            line_number=1,
            line_text="token",
        )
        f1 = Finding(secret=fake_github_pat(), **base)
        f2 = Finding(secret=fake_github_pat()[::-1], **base)
        assert f1.fingerprint != f2.fingerprint


class TestFileDiscovery:
    def test_is_probably_binary_detects_null_byte(self):
        assert is_probably_binary(b"\x00\x01\x02")
        assert not is_probably_binary(b"hello world")

    def test_iter_scannable_files_skips_excluded_dirs(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x = 1\n")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "lib.js").write_text("y = 2\n")

        found = {p.name for p in iter_scannable_files(tmp_path)}
        assert "app.py" in found
        assert "lib.js" not in found

    def test_iter_scannable_files_skips_binary_files(self, tmp_path):
        (tmp_path / "image.bin").write_bytes(b"\x00\x01binarydata")
        (tmp_path / "text.txt").write_text("hello\n")

        found = {p.name for p in iter_scannable_files(tmp_path)}
        assert "text.txt" in found
        assert "image.bin" not in found

    def test_iter_scannable_files_on_single_file(self, tmp_path):
        f = tmp_path / "solo.py"
        f.write_text("x = 1\n")
        assert list(iter_scannable_files(f)) == [f]


class TestScanFileContent:
    def test_reports_correct_line_numbers(self):
        text = f"line1\nline2\napi_key = '{AWS_KEY}'\nline4\n"
        findings = scan_file_content(text, "app.py")
        assert len(findings) == 1
        assert findings[0].line_number == 3
        assert findings[0].file_path == "app.py"

    def test_dirty_fixture_produces_multiple_findings(self):
        text = build_dirty_file_text()
        findings = scan_file_content(text, "dirty_file.py")
        rule_ids = {f.rule_id for f in findings}
        assert "aws-access-key-id" in rule_ids
        assert "github-pat" in rule_ids
        assert "private-key-block" in rule_ids
        assert len(findings) >= 5

    def test_clean_fixture_produces_no_findings(self):
        text = (FIXTURES / "clean_file.py").read_text()
        assert scan_file_content(text, "clean_file.py") == []


class TestScanPaths:
    def test_scan_paths_walks_directory_tree(self, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "secrets.py").write_text(build_dirty_file_text())
        (tmp_path / "clean.py").write_text((FIXTURES / "clean_file.py").read_text())

        findings = scan_paths([tmp_path])
        file_paths = {f.file_path for f in findings}
        assert any("secrets.py" in p for p in file_paths)
        assert not any("clean.py" in p for p in file_paths)


class TestScanGitHistory:
    def test_finds_secret_committed_and_later_removed(self, tmp_path):
        repo = tmp_path / "repo"
        _init_git_repo(repo)

        secret_file = repo / "config.py"
        secret_file.write_text(f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n')
        _run_git(repo, "add", "config.py")
        _run_git(repo, "commit", "-q", "-m", "add config with a secret")

        # "Fix" it in a later commit - the secret should still be found in history.
        secret_file.write_text('AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\n')
        _run_git(repo, "add", "config.py")
        _run_git(repo, "commit", "-q", "-m", "remove hardcoded secret")

        findings = scan_git_history(repo)

        assert any(f.rule_id == "aws-access-key-id" for f in findings)
        hit = next(f for f in findings if f.rule_id == "aws-access-key-id")
        assert hit.file_path == "config.py"
        assert hit.commit is not None
        assert hit.author == "Test User"

        # And a fresh working-tree scan should find nothing, proving history-only detection.
        working_tree_findings = scan_paths([repo / "config.py"])
        assert working_tree_findings == []

    def test_clean_history_produces_no_findings(self, tmp_path):
        repo = tmp_path / "repo"
        _init_git_repo(repo)
        (repo / "app.py").write_text("def add(a, b):\n    return a + b\n")
        _run_git(repo, "add", "app.py")
        _run_git(repo, "commit", "-q", "-m", "initial commit")

        assert scan_git_history(repo) == []

    def test_respects_max_commits(self, tmp_path):
        repo = tmp_path / "repo"
        _init_git_repo(repo)

        f = repo / "config.py"
        f.write_text(f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n')
        _run_git(repo, "add", "config.py")
        _run_git(repo, "commit", "-q", "-m", "commit with secret")

        for i in range(3):
            f.write_text(f"# revision {i}\n")
            _run_git(repo, "add", "config.py")
            _run_git(repo, "commit", "-q", "-m", f"unrelated commit {i}")

        assert scan_git_history(repo, max_commits=1) == []
        assert any(f.rule_id == "aws-access-key-id" for f in scan_git_history(repo))
