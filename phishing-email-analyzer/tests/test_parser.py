from phishscope.parser import parse_bytes


def test_parses_core_headers(analyze):
    ctx, _, _ = analyze("credential_phish.eml")
    e = ctx.email
    assert e.sender.display_name == "PayPal Security Team"
    assert e.sender.address == "service@paypa1-secure.com"
    assert e.sender.domain == "paypa1-secure.com"
    assert e.reply_to[0].domain == "protonmail-support.top"
    assert e.return_path_domain == "mailer.bulk-sender.xyz"
    assert "unusual sign-in" in e.subject


def test_collects_text_and_html_bodies(analyze):
    ctx, _, _ = analyze("credential_phish.eml")
    assert "bit.ly" in ctx.email.text_body
    assert "<form" in ctx.email.html_body


def test_attachments_are_hashed_not_executed(analyze):
    ctx, _, _ = analyze("malware_attachment.eml")
    names = {a.filename for a in ctx.email.attachments}
    assert names == {"Invoice_5521.pdf.exe", "Remittance.docm"}
    exe = next(a for a in ctx.email.attachments if a.filename.endswith(".exe"))
    assert len(exe.sha256) == 64 and len(exe.md5) == 32
    assert exe.magic.startswith(b"MZ")


def test_tolerates_minimal_message():
    e = parse_bytes(b"Subject: x\r\n\r\nbody")
    assert e.sender.address == "" and e.sender.domain == ""
    assert e.text_body.strip() == "body"
    assert e.attachments == []
