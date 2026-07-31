import json

from webauditor.auditor import AuditResult
from webauditor.fetcher import FetchResult
from webauditor.models import Finding, Severity, Status
from webauditor.report import render_json, render_text
from webauditor.tls_inspector import TLSInfo


def _sample_result():
    fetch_result = FetchResult(url="https://example.com/", final_url="https://example.com/", status=200, elapsed_ms=42.0)
    tls_info = TLSInfo(host="example.com", port=443, protocol="TLSv1.3", cipher="X", days_until_expiry=200, not_after="Jan 1 00:00:00 2030 GMT")
    findings = [
        Finding("csp", "Content-Security-Policy", Status.FAIL, Severity.HIGH, "No CSP sent.", "Add a CSP."),
        Finding("hsts", "Strict-Transport-Security", Status.PASS, Severity.INFO, "HSTS present.", None),
    ]
    return AuditResult(url="https://example.com/", fetch_result=fetch_result, tls_info=tls_info, findings=findings, score=82, grade="B")


def test_render_text_includes_key_facts():
    text = render_text(_sample_result())
    assert "https://example.com/" in text
    assert "HTTP 200" in text
    assert "Grade:    B" in text
    assert "[FAIL]" in text
    assert "No CSP sent." in text
    assert "Add a CSP." in text


def test_render_text_orders_failures_before_passes():
    text = render_text(_sample_result())
    fail_index = text.index("[FAIL]")
    pass_index = text.index("[PASS]")
    assert fail_index < pass_index


def test_render_json_round_trips():
    payload = json.loads(render_json(_sample_result()))
    assert payload["url"] == "https://example.com/"
    assert payload["grade"] == "B"
    assert payload["score"] == 82
    assert payload["tls"]["protocol"] == "TLSv1.3"
    assert len(payload["findings"]) == 2
    assert payload["findings"][0]["check_id"] == "csp"


def test_render_json_handles_missing_tls():
    result = _sample_result()
    result.tls_info = None
    payload = json.loads(render_json(result))
    assert payload["tls"] is None
