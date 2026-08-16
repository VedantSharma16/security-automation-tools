from webrecon.fingerprint import fingerprint, load_signatures


SIGNATURES = [
    {"name": "nginx", "category": "web-server", "header_patterns": {"Server": "nginx"}, "html_patterns": []},
    {
        "name": "WordPress",
        "category": "cms",
        "header_patterns": {},
        "html_patterns": ["wp-content"],
    },
]


def test_fingerprint_matches_header_pattern():
    matches = fingerprint({"Server": "nginx/1.25.0"}, "<html></html>", SIGNATURES)
    names = [m.name for m in matches]
    assert "nginx" in names
    assert "header Server" in next(m.evidence for m in matches if m.name == "nginx")


def test_fingerprint_matches_html_pattern():
    matches = fingerprint({}, "<link href='/wp-content/themes/foo.css'>", SIGNATURES)
    names = [m.name for m in matches]
    assert "WordPress" in names


def test_fingerprint_header_lookup_is_case_insensitive():
    matches = fingerprint({"server": "NGINX"}, "", SIGNATURES)
    assert any(m.name == "nginx" for m in matches)


def test_fingerprint_no_match_returns_empty_list():
    matches = fingerprint({"Server": "unknown-server"}, "<html>nothing here</html>", SIGNATURES)
    assert matches == []


def test_fingerprint_handles_none_html():
    matches = fingerprint({"Server": "nginx"}, None, SIGNATURES)
    assert any(m.name == "nginx" for m in matches)


def test_bundled_signatures_file_loads_and_is_well_formed():
    signatures = load_signatures()
    assert len(signatures) > 5
    for sig in signatures:
        assert "name" in sig
        assert "category" in sig
