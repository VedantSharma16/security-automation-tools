from recon_agent.subdomain_takeover import check_takeover, scan_for_takeover


def test_no_cname_match_is_not_vulnerable():
    result = check_takeover("www.example.com", cname_resolver=lambda h: ["www.example.com"])
    assert result.status == "not_vulnerable"
    assert result.provider is None


def test_unresolvable_subdomain_is_not_vulnerable():
    result = check_takeover("ghost.example.com", cname_resolver=lambda h: [])
    assert result.status == "not_vulnerable"


def test_matching_cname_confirmed_by_body_is_vulnerable():
    resolver = lambda h: ["ghost.example.com.github.io"]
    fetcher = lambda url, timeout: "404 - There isn't a GitHub Pages site here."

    result = check_takeover("ghost.example.com", cname_resolver=resolver, body_fetcher=fetcher)
    assert result.status == "vulnerable"
    assert result.confirmed is True
    assert result.provider == "GitHub Pages"
    assert result.cname == "ghost.example.com.github.io"


def test_matching_cname_without_confirming_body_is_possible():
    resolver = lambda h: ["shop.example.com.myshopify.com"]
    fetcher = lambda url, timeout: "Welcome to our store"  # doesn't match the fingerprint text

    result = check_takeover("shop.example.com", cname_resolver=resolver, body_fetcher=fetcher)
    assert result.status == "possible"
    assert result.confirmed is False
    assert result.provider == "Shopify"


def test_unreachable_host_still_flags_possible_from_cname_alone():
    resolver = lambda h: ["blog.example.com.herokuapp.com"]

    def failing_fetcher(url, timeout):
        raise OSError("connection refused")

    result = check_takeover("blog.example.com", cname_resolver=resolver, body_fetcher=failing_fetcher)
    assert result.status == "possible"
    assert result.provider == "Heroku"


def test_scan_for_takeover_filters_to_flagged_only():
    resolvable = {
        "safe.example.com": ["safe.example.com"],
        "dangling.example.com": ["dangling.example.com.github.io"],
    }
    resolver = lambda h: resolvable.get(h, [])
    fetcher = lambda url, timeout: "There isn't a GitHub Pages site here."

    results = scan_for_takeover(
        ["safe.example.com", "dangling.example.com"], cname_resolver=resolver, body_fetcher=fetcher
    )
    assert len(results) == 1
    assert results[0].subdomain == "dangling.example.com"
    assert results[0].status == "vulnerable"


def test_scan_for_takeover_empty_input():
    assert scan_for_takeover([]) == []
