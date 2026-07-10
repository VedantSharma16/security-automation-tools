from logtriage.ioc import extract_iocs


def test_extracts_ip_address():
    iocs = extract_iocs("Failed login attempt from 203.0.113.5 on port 22")
    assert "203.0.113.5" in iocs["ips"]


def test_extracts_url_and_excludes_its_host_from_domains_is_not_required():
    text = "Payload fetched from https://malicious-domain.example/payload.sh via curl"
    iocs = extract_iocs(text)
    assert "https://malicious-domain.example/payload.sh" in iocs["urls"]
    assert "malicious-domain.example" in iocs["domains"]


def test_ip_addresses_are_not_reported_as_domains():
    iocs = extract_iocs("connection from 198.51.100.9 refused")
    assert "198.51.100.9" not in iocs["domains"]


def test_extracts_hashes_by_length():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"[:64]
    text = f"md5={md5} sha1={sha1} sha256={sha256}"

    iocs = extract_iocs(text)
    assert md5 in iocs["md5"]
    assert sha1 in iocs["sha1"]
    assert sha256 in iocs["sha256"]


def test_extracts_email():
    iocs = extract_iocs("Suspicious mail from attacker@evil-example.com")
    assert "attacker@evil-example.com" in iocs["emails"]


def test_deduplicates_repeated_indicators():
    text = "203.0.113.5 tried again from 203.0.113.5"
    iocs = extract_iocs(text)
    assert iocs["ips"].count("203.0.113.5") == 1


def test_no_false_positives_on_plain_text():
    iocs = extract_iocs("this is just a normal log line with no indicators")
    assert iocs["ips"] == []
    assert iocs["urls"] == []
    assert iocs["md5"] == iocs["sha1"] == iocs["sha256"] == []
