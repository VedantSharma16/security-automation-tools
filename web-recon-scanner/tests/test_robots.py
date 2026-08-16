from webrecon.robots import parse_robots_txt, parse_sitemap_xml


def test_parse_robots_txt_extracts_disallow_and_sitemap():
    text = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /private/backup\n"
        "Disallow: /public\n"
        "Sitemap: https://example.com/sitemap.xml\n"
        "# a comment\n"
    )
    findings = parse_robots_txt(text)
    assert findings.disallowed_paths == ("/admin", "/private/backup", "/public")
    assert findings.sitemaps == ("https://example.com/sitemap.xml",)


def test_parse_robots_txt_flags_sensitive_paths():
    text = "Disallow: /admin\nDisallow: /public\nDisallow: /wp-admin\n"
    findings = parse_robots_txt(text)
    assert "/admin" in findings.sensitive_paths
    assert "/wp-admin" in findings.sensitive_paths
    assert "/public" not in findings.sensitive_paths


def test_parse_robots_txt_handles_empty_and_malformed_input():
    assert parse_robots_txt("").disallowed_paths == ()
    assert parse_robots_txt(None).disallowed_paths == ()
    assert parse_robots_txt("not a valid line\n\n# comment").disallowed_paths == ()


def test_parse_sitemap_xml_extracts_loc_urls():
    xml = (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<urlset><url><loc>https://example.com/</loc></url>"
        "<url><loc>https://example.com/about</loc></url></urlset>"
    )
    urls = parse_sitemap_xml(xml)
    assert urls == ["https://example.com/", "https://example.com/about"]


def test_parse_sitemap_xml_handles_empty_input():
    assert parse_sitemap_xml("") == []
    assert parse_sitemap_xml(None) == []
