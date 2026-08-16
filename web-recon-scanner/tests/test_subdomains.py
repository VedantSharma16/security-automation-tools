from webrecon.subdomains import enumerate_subdomains, load_wordlist


def fake_resolver(known):
    def resolve(fqdn):
        if fqdn in known:
            return known[fqdn]
        raise OSError("name resolution failed")

    return resolve


def test_enumerate_subdomains_returns_only_resolved_entries():
    resolver = fake_resolver({"www.example.com": "93.184.216.34", "api.example.com": "93.184.216.35"})
    results = enumerate_subdomains("example.com", ["www", "api", "doesnotexist"], resolver=resolver)

    resolved_names = [r.subdomain for r in results]
    assert resolved_names == ["api.example.com", "www.example.com"]
    assert all(r.resolved for r in results)


def test_enumerate_subdomains_no_matches_returns_empty_list():
    resolver = fake_resolver({})
    results = enumerate_subdomains("example.com", ["a", "b", "c"], resolver=resolver)
    assert results == []


def test_enumerate_subdomains_results_sorted_alphabetically():
    resolver = fake_resolver({"z.example.com": "1.1.1.1", "a.example.com": "2.2.2.2"})
    results = enumerate_subdomains("example.com", ["z", "a"], resolver=resolver)
    assert [r.subdomain for r in results] == ["a.example.com", "z.example.com"]


def test_bundled_wordlist_loads_and_is_non_empty():
    words = load_wordlist()
    assert len(words) > 10
    assert "www" in words
    assert all(not w.startswith("#") for w in words)
