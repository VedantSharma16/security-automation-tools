from __future__ import annotations

from recon_agent.findings import derive_findings, overall_severity


def test_no_findings_when_results_are_clean():
    tool_results = {
        "subdomain_enum": [{"domain": "example.com", "checked": 3, "discovered": []}],
        "http_probe": [{"host": "example.com", "reachable": True, "missing_security_headers": []}],
        "tls_probe": [{"host": "example.com", "reachable": True, "protocol": "TLSv1.3", "days_until_expiry": 200}],
    }
    findings = derive_findings(tool_results)
    assert findings == []
    assert overall_severity(findings) == "info"


def test_sensitive_subdomain_flagged_medium():
    tool_results = {
        "subdomain_enum": [{
            "domain": "example.com",
            "checked": 1,
            "discovered": [{"subdomain": "admin.example.com", "addresses": ["10.0.0.1"], "sensitive": True}],
        }],
    }
    findings = derive_findings(tool_results)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].category == "exposed-subdomain"


def test_missing_security_headers_scales_with_count():
    few_missing = {"http_probe": [{
        "host": "a.example.com", "reachable": True, "missing_security_headers": ["Content-Security-Policy"],
    }]}
    many_missing = {"http_probe": [{
        "host": "b.example.com", "reachable": True,
        "missing_security_headers": ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"],
    }]}

    assert derive_findings(few_missing)[0].severity == "low"
    assert derive_findings(many_missing)[0].severity == "medium"


def test_unreachable_http_host_produces_no_header_finding():
    tool_results = {"http_probe": [{"host": "dead.example.com", "reachable": False, "error": "timeout"}]}
    assert derive_findings(tool_results) == []


def test_expired_certificate_is_critical():
    tool_results = {"tls_probe": [{
        "host": "example.com", "reachable": True, "protocol": "TLSv1.3", "days_until_expiry": -5,
    }]}
    findings = derive_findings(tool_results)
    assert findings[0].severity == "critical"
    assert findings[0].category == "expired-certificate"


def test_soon_expiring_certificate_severity_thresholds():
    tool_results_high = {"tls_probe": [{"host": "a", "reachable": True, "protocol": "TLSv1.3", "days_until_expiry": 5}]}
    tool_results_medium = {"tls_probe": [{"host": "b", "reachable": True, "protocol": "TLSv1.3", "days_until_expiry": 20}]}
    tool_results_none = {"tls_probe": [{"host": "c", "reachable": True, "protocol": "TLSv1.3", "days_until_expiry": 90}]}

    assert derive_findings(tool_results_high)[0].severity == "high"
    assert derive_findings(tool_results_medium)[0].severity == "medium"
    assert derive_findings(tool_results_none) == []


def test_weak_tls_protocol_flagged_high():
    tool_results = {"tls_probe": [{
        "host": "example.com", "reachable": True, "protocol": "TLSv1.1", "days_until_expiry": 200,
    }]}
    findings = derive_findings(tool_results)
    assert any(f.category == "weak-tls-protocol" and f.severity == "high" for f in findings)


def test_overall_severity_takes_the_max():
    tool_results = {
        "http_probe": [{"host": "a", "reachable": True, "missing_security_headers": ["X-Frame-Options"]}],
        "tls_probe": [{"host": "a", "reachable": True, "protocol": "TLSv1.3", "days_until_expiry": -1}],
    }
    findings = derive_findings(tool_results)
    assert overall_severity(findings) == "critical"


def test_findings_sorted_most_severe_first():
    tool_results = {
        "http_probe": [{"host": "a", "reachable": True, "missing_security_headers": ["X-Frame-Options"]}],
        "tls_probe": [{"host": "a", "reachable": True, "protocol": "TLSv1.3", "days_until_expiry": -1}],
    }
    findings = derive_findings(tool_results)
    assert findings[0].severity == "critical"
    assert findings[-1].severity == "low"
