import pytest


def test_credential_phish_rules(analyze):
    _, _, rules = analyze("credential_phish.eml")
    assert {
        "auth.dmarc_fail", "auth.spf_fail", "header.display_name_brand", "header.lookalike_sender",
        "header.reply_to_mismatch", "link.text_href_mismatch", "link.lookalike_domain",
        "link.shortener", "content.embedded_form", "content.urgency_lure",
    } <= rules


def test_malware_attachment_rules(analyze):
    _, findings, rules = analyze("malware_attachment.eml")
    assert {"attachment.double_extension", "attachment.macro_office", "auth.spf_fail", "auth.dkim_fail"} <= rules
    assert findings[0].severity == "CRITICAL"  # sorted most severe first
    assert findings[0].technique == "T1036.007"


def test_prompt_injection_email_with_passing_auth(analyze):
    # Fully authenticated sender: auth alone would call this clean.
    _, findings, rules = analyze("ai_prompt_injection.eml")
    assert not any(r.startswith("auth.") for r in rules)
    assert {"content.prompt_injection", "content.hidden_text", "link.lookalike_domain"} <= rules
    inj = next(f for f in findings if f.rule == "content.prompt_injection")
    assert inj.technique.startswith("AML.")


def test_benign_email_has_no_findings(analyze):
    _, findings, _ = analyze("benign_notification.eml")
    assert findings == []


def test_display_name_with_embedded_address(analyze, make_eml):
    raw = make_eml({"From": '"ceo@corp.example" <ceo.office@gmail.com>',
                    "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass"})
    _, _, rules = analyze(raw)
    assert "header.display_name_address" in rules


@pytest.mark.parametrize("url,rule", [
    ("http://192.0.2.10/login", "link.ip_host"),
    ("https://xn--pypal-4ve.com/", "link.punycode"),
    ("https://files.example.zip/a", "link.suspicious_tld"),
    ("https://www.paypal.com@evil.test/login", "link.userinfo_obfuscation"),
    ("https://tinyurl.com/abc", "link.shortener"),
])
def test_link_rules(analyze, make_eml, url, rule):
    _, _, rules = analyze(make_eml(body=f"Click {url} now"))
    assert rule in rules


def test_magic_bytes_mismatch(analyze):
    from email.message import EmailMessage

    m = EmailMessage()
    m["From"] = "a@example.org"
    m["Authentication-Results"] = "mx; spf=pass; dkim=pass; dmarc=pass"
    m.set_content("see attached")
    m.add_attachment(b"MZ\x90\x00inert-fixture", maintype="application", subtype="pdf", filename="report.pdf")
    _, findings, rules = analyze(bytes(m))
    assert "attachment.magic_mismatch" in rules
    assert any(f.severity == "CRITICAL" for f in findings)


def test_html_attachment_flagged(analyze):
    from email.message import EmailMessage

    m = EmailMessage()
    m["From"] = "a@example.org"
    m.set_content("voicemail")
    m.add_attachment(b"<html></html>", maintype="text", subtype="html", filename="Voicemail_0412.htm")
    _, _, rules = analyze(bytes(m))
    assert "attachment.html" in rules
    assert "auth.no_results" in rules


def test_reply_to_same_org_subdomain_is_fine(analyze, make_eml):
    raw = make_eml({"From": "a@mail.example.org", "Reply-To": "support@help.example.org"})
    _, _, rules = analyze(raw)
    assert "header.reply_to_mismatch" not in rules
