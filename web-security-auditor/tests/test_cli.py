import json

from webauditor import cli
from webauditor.auditor import AuditResult
from webauditor.fetcher import FetchResult


def _result(url, grade, score):
    return AuditResult(
        url=url,
        fetch_result=FetchResult(url=url, final_url=url, status=200),
        tls_info=None,
        findings=[],
        score=score,
        grade=grade,
    )


def test_main_prints_text_report(monkeypatch, capsys):
    monkeypatch.setattr(cli, "audit_url", lambda url, timeout, skip_tls: _result(url, "A", 100))

    exit_code = cli.main(["https://example.com/"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "https://example.com/" in captured.out
    assert "Grade:    A" in captured.out


def test_main_prints_json_report(monkeypatch, capsys):
    monkeypatch.setattr(cli, "audit_url", lambda url, timeout, skip_tls: _result(url, "A", 100))

    cli.main(["https://example.com/", "--json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload[0]["grade"] == "A"


def test_main_separates_multiple_urls(monkeypatch, capsys):
    monkeypatch.setattr(cli, "audit_url", lambda url, timeout, skip_tls: _result(url, "A", 100))

    cli.main(["https://one.example/", "https://two.example/"])

    captured = capsys.readouterr()
    assert captured.out.count("Target:") == 2


def test_min_grade_fails_build_when_score_too_low(monkeypatch):
    monkeypatch.setattr(cli, "audit_url", lambda url, timeout, skip_tls: _result(url, "D", 65))

    exit_code = cli.main(["https://example.com/", "--min-grade", "B"])

    assert exit_code == 1


def test_min_grade_passes_when_score_is_high_enough(monkeypatch):
    monkeypatch.setattr(cli, "audit_url", lambda url, timeout, skip_tls: _result(url, "A", 100))

    exit_code = cli.main(["https://example.com/", "--min-grade", "B"])

    assert exit_code == 0


def test_no_tls_flag_is_forwarded(monkeypatch):
    seen = {}

    def fake_audit(url, timeout, skip_tls):
        seen["skip_tls"] = skip_tls
        return _result(url, "A", 100)

    monkeypatch.setattr(cli, "audit_url", fake_audit)

    cli.main(["https://example.com/", "--no-tls"])

    assert seen["skip_tls"] is True
