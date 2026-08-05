import json

from websecaudit.fetcher import FetchResult
from websecaudit.report import build_report, render_console, render_markdown, write_json, write_markdown
from websecaudit.scanner import analyze

WEAK_FETCH = FetchResult(
    requested_url="http://weak.example",
    final_url="http://weak.example",
    status_code=200,
    scheme="http",
    headers={},
    set_cookie_headers=["session=abc"],
    redirect_chain=[],
)


def test_build_report_structure():
    report = build_report(analyze(WEAK_FETCH))
    assert report["requested_url"] == "http://weak.example"
    assert report["grade"] in {"A+", "A", "B", "C", "D", "F"}
    assert report["finding_count"] == len(report["findings"])
    assert sum(report["severity_counts"].values()) == report["finding_count"]


def test_render_console_contains_grade_and_findings(capsys):
    report = build_report(analyze(WEAK_FETCH))
    text = render_console(report, use_color=False)
    assert "Grade:" in text
    assert "plaintext-http" in text
    assert "\033[" not in text  # no ANSI codes when use_color=False


def test_render_console_uses_color_codes_when_enabled():
    report = build_report(analyze(WEAK_FETCH))
    text = render_console(report, use_color=True)
    assert "\033[" in text


def test_render_markdown_has_table():
    report = build_report(analyze(WEAK_FETCH))
    md = render_markdown(report)
    assert "| Severity | ID |" in md
    assert "plaintext-http" in md


def test_write_json_roundtrip(tmp_path):
    report = build_report(analyze(WEAK_FETCH))
    out = tmp_path / "report.json"
    write_json(report, out)
    loaded = json.loads(out.read_text())
    assert loaded["grade"] == report["grade"]


def test_write_markdown_creates_file(tmp_path):
    report = build_report(analyze(WEAK_FETCH))
    out = tmp_path / "report.md"
    write_markdown(report, out)
    assert out.exists()
    assert "Web Security Audit" in out.read_text()


def test_clean_report_has_checkmark():
    from websecaudit.fetcher import TLSInfo

    good = FetchResult(
        requested_url="https://good.example",
        final_url="https://good.example",
        status_code=200,
        scheme="https",
        headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
        },
        set_cookie_headers=[],
        redirect_chain=[],
        tls=TLSInfo(protocol_version="TLSv1.3", days_until_expiry=200),
    )
    report = build_report(analyze(good))
    text = render_console(report, use_color=False)
    assert "No issues found" in text
