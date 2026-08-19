from webrecon.fingerprint import identify, load_signatures


def test_load_signatures_returns_well_formed_entries():
    sigs = load_signatures()
    assert len(sigs) > 10
    for sig in sigs:
        assert {"name", "category", "match"} <= sig.keys()
        assert sig["match"]["type"] in {"header", "body"}


def test_identify_matches_header_signature():
    matches = identify({"Server": "nginx/1.18.0"}, body="")
    names = {m.name for m in matches}
    assert "nginx" in names


def test_identify_matches_body_signature():
    matches = identify({}, body="<div class='wp-content'>hi</div>")
    names = {m.name for m in matches}
    assert "WordPress" in names


def test_identify_deduplicates_technology_across_multiple_matching_rules():
    # Cloudflare has both a Server-header rule and a cf-ray-header rule.
    matches = identify({"Server": "cloudflare", "CF-RAY": "abc123"}, body="")
    cloudflare_matches = [m for m in matches if m.name == "Cloudflare"]
    assert len(cloudflare_matches) == 1


def test_identify_returns_empty_list_when_nothing_matches():
    matches = identify({"Content-Type": "text/plain"}, body="plain text, nothing interesting here")
    assert matches == []
