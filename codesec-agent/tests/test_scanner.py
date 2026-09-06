from codesec_agent.scanner import discover_python_files, scan_directory, scan_file


VULNERABLE_SNIPPET = "import os\ndef f(x):\n    os.system(x)\n"
CLEAN_SNIPPET = "def add(a, b):\n    return a + b\n"


def test_discover_python_files_skips_vendor_dirs(tmp_path):
    (tmp_path / "app.py").write_text(CLEAN_SNIPPET)
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "lib.py").write_text(CLEAN_SNIPPET)
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook.py").write_text(CLEAN_SNIPPET)
    (tmp_path / "notes.txt").write_text("not python")

    found = {p.relative_to(tmp_path) for p in discover_python_files(tmp_path)}
    assert found == {tmp_path.joinpath("app.py").relative_to(tmp_path)}


def test_discover_python_files_on_single_file(tmp_path):
    f = tmp_path / "app.py"
    f.write_text(CLEAN_SNIPPET)
    assert discover_python_files(f) == [f]

    txt = tmp_path / "notes.txt"
    txt.write_text("x")
    assert discover_python_files(txt) == []


def test_scan_directory_aggregates_findings_across_files(tmp_path):
    (tmp_path / "safe.py").write_text(CLEAN_SNIPPET)
    (tmp_path / "vuln.py").write_text(VULNERABLE_SNIPPET)

    result = scan_directory(tmp_path)

    assert sorted(result.files_scanned) == ["safe.py", "vuln.py"]
    assert len(result.findings) == 1
    assert result.findings[0].file == "vuln.py"
    assert result.parse_errors == []


def test_scan_directory_handles_syntax_errors_gracefully(tmp_path):
    (tmp_path / "broken.py").write_text("def f(:\n    pass\n")
    (tmp_path / "vuln.py").write_text(VULNERABLE_SNIPPET)

    result = scan_directory(tmp_path)

    assert result.files_scanned == ["vuln.py"]
    assert len(result.parse_errors) == 1
    assert result.parse_errors[0][0] == "broken.py"


def test_scan_directory_sorts_by_severity_then_file_and_line():
    import textwrap

    src = textwrap.dedent(
        """
        import hashlib
        hashlib.md5(b'x')  # medium

        def f(x):
            eval(x)  # high
        """
    )

    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "mixed.py").write_text(src)
        result = scan_directory(root)

    severities = [f.severity for f in result.findings]
    assert severities == sorted(severities, key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}[s])


def test_scan_file_uses_root_relative_display_name(tmp_path):
    sub = tmp_path / "pkg"
    sub.mkdir()
    f = sub / "mod.py"
    f.write_text(VULNERABLE_SNIPPET)

    findings = scan_file(f, root=tmp_path)
    assert findings[0].file == "pkg/mod.py"
