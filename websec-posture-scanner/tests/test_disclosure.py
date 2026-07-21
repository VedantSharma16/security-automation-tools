from webscan.checks.disclosure import check_info_disclosure
from webscan.models import ScanTarget


def _target(headers: dict) -> ScanTarget:
    url = "https://example.com/"
    return ScanTarget(url=url, final_url=url, status_code=200, headers=headers, raw_headers=list(headers.items()))


def test_no_disclosure_headers_no_findings():
    assert check_info_disclosure(_target({})) == []


def test_server_version_disclosed():
    findings = check_info_disclosure(_target({"server": "nginx/1.18.0"}))
    assert "disclosure-server-version" in [f.id for f in findings]


def test_server_without_version_not_flagged():
    findings = check_info_disclosure(_target({"server": "nginx"}))
    assert findings == []


def test_x_powered_by_disclosed():
    findings = check_info_disclosure(_target({"x-powered-by": "PHP/8.1.2"}))
    assert "disclosure-x-powered-by" in [f.id for f in findings]


def test_aspnet_version_disclosed():
    findings = check_info_disclosure(_target({"x-aspnet-version": "4.0.30319"}))
    assert "disclosure-x-aspnet-version" in [f.id for f in findings]


def test_multiple_disclosure_headers_all_reported():
    findings = check_info_disclosure(
        _target({"server": "Apache/2.4.41", "x-powered-by": "Express"})
    )
    ids = {f.id for f in findings}
    assert "disclosure-server-version" in ids
    assert "disclosure-x-powered-by" in ids
