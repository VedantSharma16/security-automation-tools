from recon.dns_enum import ResolvedHost, analyze_subdomains, enumerate_subdomains, load_wordlist


def fake_resolver(known: dict):
    def resolver(hostname: str):
        return known.get(hostname)

    return resolver


def test_load_wordlist_has_entries():
    words = load_wordlist()
    assert len(words) > 10
    assert "admin" in words
    assert "www" in words


def test_enumerate_subdomains_only_returns_resolved_hosts():
    known = {"www.example.com": "1.2.3.4", "admin.example.com": "1.2.3.5"}
    resolved = enumerate_subdomains(
        "example.com", wordlist=["www", "admin", "doesnotexist"], resolver=fake_resolver(known)
    )
    hostnames = {h.hostname for h in resolved}
    assert hostnames == {"www.example.com", "admin.example.com"}


def test_enumerate_subdomains_empty_when_nothing_resolves():
    resolved = enumerate_subdomains(
        "example.com", wordlist=["ghost1", "ghost2"], resolver=fake_resolver({})
    )
    assert resolved == []


def test_analyze_subdomains_no_findings_when_empty():
    assert analyze_subdomains("example.com", []) == []


def test_analyze_subdomains_flags_noteworthy_labels():
    resolved = [
        ResolvedHost("www.example.com", "1.1.1.1"),
        ResolvedHost("admin.example.com", "1.1.1.2"),
        ResolvedHost("staging.example.com", "1.1.1.3"),
    ]
    findings = analyze_subdomains("example.com", resolved)
    titles = [f.title for f in findings]
    assert any("Non-production or admin-facing" in t for t in titles)
    noteworthy_finding = next(f for f in findings if "Non-production" in f.title)
    assert set(noteworthy_finding.evidence["hosts"]) == {
        "admin.example.com",
        "staging.example.com",
    }


def test_analyze_subdomains_flags_wildcard_pattern():
    resolved = [ResolvedHost(f"h{i}.example.com", "9.9.9.9") for i in range(5)]
    findings = analyze_subdomains("example.com", resolved)
    assert any("wildcard" in f.title.lower() for f in findings)


def test_analyze_subdomains_no_wildcard_flag_with_distinct_ips():
    resolved = [ResolvedHost(f"h{i}.example.com", f"9.9.9.{i}") for i in range(5)]
    findings = analyze_subdomains("example.com", resolved)
    assert not any("wildcard" in f.title.lower() for f in findings)
