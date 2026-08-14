from __future__ import annotations

from asmapper.fingerprint import fingerprint, load_signatures
from asmapper.models import Severity

SIGS = [
    {
        "name": "WordPress",
        "category": "CMS",
        "header_signatures": [{"header": "link", "contains": "wp-json"}],
        "body_signatures": ["wp-content/"],
        "note": "Check the version.",
    },
    {
        "name": "Nginx",
        "category": "web-server",
        "header_signatures": [{"header": "server", "contains": "nginx"}],
        "body_signatures": [],
        "note": "",
    },
]


def test_matches_via_header_signature():
    findings = fingerprint({"Server": "nginx/1.18.0"}, "", signatures=SIGS)
    assert len(findings) == 1
    assert findings[0].id == "fingerprint-nginx"
    assert findings[0].severity == Severity.INFO


def test_matches_via_body_signature():
    findings = fingerprint({}, "<link rel='stylesheet' href='/wp-content/themes/foo/style.css'>", signatures=SIGS)
    assert any(f.id == "fingerprint-wordpress" for f in findings)


def test_no_match_returns_empty_list():
    findings = fingerprint({"Server": "Caddy"}, "<html></html>", signatures=SIGS)
    assert findings == []


def test_multiple_matches_are_all_reported():
    findings = fingerprint(
        {"Server": "nginx"}, "<link href='/wp-content/style.css'>", signatures=SIGS
    )
    ids = {f.id for f in findings}
    assert ids == {"fingerprint-nginx", "fingerprint-wordpress"}


def test_default_signatures_file_loads_and_is_well_formed():
    sigs = load_signatures()
    assert len(sigs) > 5
    for sig in sigs:
        assert "name" in sig and "category" in sig
        assert "header_signatures" in sig and "body_signatures" in sig
