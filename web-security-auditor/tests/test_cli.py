import json

import pytest

from websecaudit import cli
from websecaudit.fetcher import FetchResult

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
}


def _good_fetch(url, **kwargs):
    return FetchResult(
        requested_url=url, final_url=url, status_code=200, scheme="https",
        headers=GOOD_HEADERS, set_cookie_headers=[], redirect_chain=[],
    )


def _weak_fetch(url, **kwargs):
    return FetchResult(
        requested_url=url, final_url=url, status_code=200, scheme="http",
        headers={}, set_cookie_headers=["session=abc"], redirect_chain=[],
    )


def _error_fetch(url, **kwargs):
    return FetchResult(
        requested_url=url, final_url=url, status_code=0, scheme="https",
        error="Connection refused",
    )


def test_clean_site_exits_zero(capsys):
    code = cli.run(["https://good.example", "--no-color"], fetch=_good_fetch)
    assert code == cli.EXIT_CLEAN
    assert "Grade: A+" in capsys.readouterr().out


def test_weak_site_below_min_grade_exits_findings():
    code = cli.run(["https://weak.example"], fetch=_weak_fetch)
    assert code == cli.EXIT_FINDINGS


def test_weak_site_passing_lower_min_grade_exits_clean():
    code = cli.run(["https://weak.example", "--min-grade", "F"], fetch=_weak_fetch)
    assert code == cli.EXIT_CLEAN


def test_unreachable_site_exits_error():
    code = cli.run(["https://down.example"], fetch=_error_fetch)
    assert code == cli.EXIT_ERROR


def test_json_out_writes_single_report(tmp_path):
    out = tmp_path / "report.json"
    cli.run(["https://good.example", "--json-out", str(out)], fetch=_good_fetch)
    data = json.loads(out.read_text())
    assert data["grade"] == "A+"


def test_json_out_writes_list_for_multiple_urls(tmp_path):
    out = tmp_path / "report.json"
    cli.run(
        ["https://good.example", "https://good2.example", "--json-out", str(out)],
        fetch=_good_fetch,
    )
    data = json.loads(out.read_text())
    assert isinstance(data, list)
    assert len(data) == 2


def test_md_out_writes_markdown(tmp_path):
    out = tmp_path / "report.md"
    cli.run(["https://good.example", "--md-out", str(out)], fetch=_good_fetch)
    assert "Web Security Audit" in out.read_text()


def test_input_file_urls_are_scanned(tmp_path):
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("good.example\n# a comment\n\n")
    code = cli.run(["--input-file", str(urls_file)], fetch=_good_fetch)
    assert code == cli.EXIT_CLEAN


def test_bare_hostname_defaults_to_https(capsys):
    cli.run(["good.example"], fetch=_good_fetch)
    assert "https://good.example" in capsys.readouterr().out


def test_no_urls_raises_system_exit():
    with pytest.raises(SystemExit):
        cli.run([], fetch=_good_fetch)
