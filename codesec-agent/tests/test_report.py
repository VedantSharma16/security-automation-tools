from codesec_agent.agent import CodeSecurityAgent
from codesec_agent.report import filter_by_min_severity, render_console, render_markdown, write_json

VULNERABLE_SNIPPET = "import os\nimport hashlib\n\ndef f(x):\n    os.system(x)\n\nhashlib.md5(b'x')\n"


def _report(tmp_path):
    (tmp_path / "app.py").write_text(VULNERABLE_SNIPPET)
    return CodeSecurityAgent(api_key=None).review(str(tmp_path))


def test_render_console_includes_findings_and_narrative(tmp_path):
    report = _report(tmp_path)
    text = render_console(report)
    assert "app.py:5" in text
    assert "CWE-78" in text
    assert "Review:" in text
    assert "offline heuristic summary" in text


def test_render_markdown_table_has_a_row_per_finding(tmp_path):
    report = _report(tmp_path)
    md = render_markdown(report)
    assert "| high | CWE-78 |" in md
    assert "| medium | CWE-327 |" in md
    assert md.startswith("# CodeSec Agent report")


def test_render_markdown_with_no_findings_shows_placeholder_row(tmp_path):
    (tmp_path / "safe.py").write_text("def add(a, b):\n    return a + b\n")
    report = CodeSecurityAgent(api_key=None).review(str(tmp_path))
    md = render_markdown(report)
    assert "No findings" in md


def test_filter_by_min_severity_drops_lower_findings_and_zeroes_counts(tmp_path):
    report = _report(tmp_path)
    assert report.severity_counts["medium"] == 1
    assert report.severity_counts["high"] == 1

    filtered = filter_by_min_severity(report, "high")

    assert all(f.severity in ("high", "critical") for f in filtered.findings)
    assert filtered.severity_counts["medium"] == 0
    assert filtered.severity_counts["low"] == 0
    assert filtered.severity_counts["high"] == 1


def test_filter_by_min_severity_rejects_unknown_severity(tmp_path):
    report = _report(tmp_path)
    try:
        filter_by_min_severity(report, "apocalyptic")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_write_json_produces_loadable_report(tmp_path):
    import json

    report = _report(tmp_path)
    out = tmp_path / "report.json"
    write_json(report, out)

    loaded = json.loads(out.read_text())
    assert loaded["findings"][0]["rule_id"] == "command-injection"
