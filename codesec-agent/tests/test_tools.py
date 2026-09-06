import pytest

from codesec_agent.tools import (
    ToolError,
    execute_tool,
    grep_pattern,
    list_python_files,
    read_file,
    run_static_rules,
)

VULNERABLE_SNIPPET = "import os\ndef f(x):\n    os.system(x)\n"


@pytest.fixture()
def project(tmp_path):
    (tmp_path / "app.py").write_text(VULNERABLE_SNIPPET)
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "mod.py").write_text("def add(a, b):\n    return a + b\n")
    return tmp_path


def test_list_python_files(project):
    result = list_python_files(str(project))
    assert set(result["files"]) == {"app.py", "pkg/mod.py"}


def test_read_file_returns_content(project):
    result = read_file(str(project), "app.py")
    assert result["content"] == VULNERABLE_SNIPPET
    assert result["truncated"] is False


def test_read_file_truncates_large_files(project):
    (project / "big.py").write_text("x = 1\n" * 5000)
    result = read_file(str(project), "big.py", max_bytes=100)
    assert result["truncated"] is True
    assert len(result["content"]) == 100


def test_read_file_rejects_path_outside_root(project):
    with pytest.raises(ToolError):
        read_file(str(project), "../outside.py")


def test_read_file_rejects_absolute_path_outside_root(project, tmp_path_factory):
    other = tmp_path_factory.mktemp("elsewhere") / "secret.py"
    other.write_text("secret = 1\n")
    with pytest.raises(ToolError):
        read_file(str(project), str(other))


def test_read_file_missing_file_raises(project):
    with pytest.raises(ToolError):
        read_file(str(project), "does_not_exist.py")


def test_run_static_rules_returns_findings(project):
    result = run_static_rules(str(project), "app.py")
    assert result["path"] == "app.py"
    assert result["findings"][0]["rule_id"] == "command-injection"


def test_run_static_rules_handles_syntax_error(project):
    (project / "broken.py").write_text("def f(:\n")
    result = run_static_rules(str(project), "broken.py")
    assert result["findings"] == []
    assert "error" in result


def test_grep_pattern_finds_matches(project):
    result = grep_pattern(str(project), pattern=r"os\.system")
    assert len(result["matches"]) == 1
    assert result["matches"][0]["path"] == "app.py"


def test_grep_pattern_rejects_invalid_regex(project):
    with pytest.raises(ToolError):
        grep_pattern(str(project), pattern="(unclosed")


def test_execute_tool_dispatches_by_name(project):
    result = execute_tool("read_file", {"path": "app.py"}, root=str(project))
    assert result["content"] == VULNERABLE_SNIPPET


def test_execute_tool_unknown_name_returns_error_dict(project):
    result = execute_tool("delete_everything", {}, root=str(project))
    assert "error" in result


def test_execute_tool_catches_tool_error(project):
    result = execute_tool("read_file", {"path": "../escape.py"}, root=str(project))
    assert "error" in result


def test_execute_tool_catches_bad_arguments(project):
    result = execute_tool("read_file", {"nonexistent_kwarg": 1}, root=str(project))
    assert "error" in result
