from __future__ import annotations

from recon_agent.http_recon import SECURITY_HEADERS, HttpFinding, RobotsFinding
from recon_agent.scoring import score_findings
from recon_agent.tls_recon import TlsFinding


def test_score_findings_clean_target_is_info():
    http_finding = HttpFinding(url="https://example.com", status=200, missing_security_headers=[])
    robots_finding = RobotsFinding(url="https://example.com/robots.txt", fetched=True)
    tls_finding = TlsFinding(host="example.com", port=443, connected=True, protocol="TLSv1.3")

    assessment = score_findings(http_finding, robots_finding, tls_finding)

    assert assessment.score == 0
    assert assessment.severity == "info"


def test_score_findings_penalizes_missing_headers_and_fingerprint():
    http_finding = HttpFinding(
        url="https://example.com",
        status=200,
        missing_security_headers=["strict-transport-security", "content-security-policy"],
        fingerprint={"server": "Apache/2.2.3"},
    )

    assessment = score_findings(http_finding=http_finding)

    assert assessment.score == 1 + 1 + 2
    reasons = [f.reason for f in assessment.findings]
    assert any("Missing security header" in r for r in reasons)
    assert any("fingerprinting" in r for r in reasons)


def test_score_findings_flags_sensitive_robots_paths():
    robots_finding = RobotsFinding(
        url="https://example.com/robots.txt",
        fetched=True,
        disallowed_paths=["/blog", "/wp-admin", "/backup-2023"],
    )

    assessment = score_findings(robots_finding=robots_finding)

    reasons = [f.reason for f in assessment.findings]
    assert any("wp-admin" in r for r in reasons)
    assert any("backup-2023" in r for r in reasons)
    assert not any("/blog" in r for r in reasons)


def test_score_findings_expired_cert_outweighs_expiring_soon():
    expired = TlsFinding(host="a", port=443, connected=True, issues=["Certificate expired 5 day(s) ago"])
    expiring = TlsFinding(host="b", port=443, connected=True, issues=["Certificate expires in 5 day(s)"])

    expired_score = score_findings(tls_finding=expired).score
    expiring_score = score_findings(tls_finding=expiring).score

    assert expired_score > expiring_score


def test_score_findings_penalizes_failed_tls_connection():
    tls_finding = TlsFinding(host="a", port=443, connected=False, error="timed out")

    assessment = score_findings(tls_finding=tls_finding)

    assert assessment.score >= 3
    assert assessment.severity in {"low", "medium", "high"}


def test_severity_bands_are_monotonic():
    assert score_findings().severity == "info"

    high_http = HttpFinding(
        url="u",
        missing_security_headers=list(SECURITY_HEADERS),
        fingerprint={"server": "Apache/2.2.3"},
    )
    tls_bad = TlsFinding(host="a", port=443, connected=True, issues=["Certificate expired 1 day(s) ago"])
    assessment = score_findings(http_finding=high_http, tls_finding=tls_bad)
    assert assessment.severity == "high"
