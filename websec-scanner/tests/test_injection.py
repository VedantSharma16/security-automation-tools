from __future__ import annotations

from websec.checks.injection import (
    SQLI_PAYLOAD,
    XSS_MARKER,
    build_probes,
    check_reflected_xss,
    check_sql_injection,
)
from websec.models import Endpoint


def test_build_probes_covers_every_param_with_both_payload_kinds():
    endpoint = Endpoint(url="http://x/search", params={"q": "test", "page": "1"})
    probes = build_probes(endpoint)
    kinds_by_param = {}
    for param, kind, url in probes:
        kinds_by_param.setdefault(param, set()).add(kind)
        assert param in url
    assert kinds_by_param == {"q": {"xss", "sqli"}, "page": {"xss", "sqli"}}


def test_reflected_xss_detected_on_verbatim_reflection():
    endpoint = Endpoint(url="http://x/search", params={"q": "test"})
    body = f"<html>Results for: {XSS_MARKER}</html>"
    finding = check_reflected_xss(endpoint, "q", 200, body, "http://x/search?q=...")
    assert finding is not None
    assert finding.severity.value == "high"


def test_reflected_xss_not_flagged_when_absent():
    endpoint = Endpoint(url="http://x/search", params={"q": "test"})
    body = "<html>Results for: &lt;script&gt;</html>"
    assert check_reflected_xss(endpoint, "q", 200, body, "http://x/search?q=...") is None


def test_sql_injection_detected_on_db_error_signature():
    endpoint = Endpoint(url="http://x/users", params={"id": "1"})
    body = "Warning: mysqli_query(): You have an error in your SQL syntax"
    finding = check_sql_injection(endpoint, "id", 200, body, "http://x/users?id=1'")
    assert finding is not None
    assert finding.severity.value == "critical"


def test_sql_injection_not_flagged_on_clean_response():
    endpoint = Endpoint(url="http://x/users", params={"id": "1"})
    assert check_sql_injection(endpoint, "id", 200, "<html>User 1</html>", "http://x/users?id=1") is None
