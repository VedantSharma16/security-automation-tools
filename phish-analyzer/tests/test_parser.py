from pathlib import Path

from phishlens.parser import extract_text_urls, parse_bytes, parse_file

FIX = Path(__file__).parent / "fixtures"


def test_parse_headers_and_addresses():
    e = parse_file(FIX / "credential_phish.eml")
    assert e.sender.display_name == "PayPal Security"
    assert e.sender.email == "service@paypa1-security.com"
    assert e.sender.domain == "paypa1-security.com"
    assert e.reply_to[0].email == "support-desk@protonmail.example"
    assert e.return_path == "bounce@mailer-out.click"
    assert len(e.auth_results) == 2


def test_received_chain_extracts_peer_ip():
    e = parse_file(FIX / "credential_phish.eml")
    assert len(e.received) == 2
    assert e.received[0].ip == "10.20.0.5"
    assert e.received[1].ip == "203.0.113.45"
    assert e.received[1].from_host == "paypa1-security.com"


def test_html_links_keep_anchor_text_and_dedupe_text_urls():
    e = parse_file(FIX / "credential_phish.eml")
    anchors = {l.url: l.text for l in e.links if l.source == "html"}
    assert anchors["http://paypa1-security.com/login/verify.php?id=88213"] == "https://www.paypal.com/signin"
    assert "http://198.51.100.23/t.gif?u=j.doe" in anchors  # tracking pixel captured
    urls = [l.url for l in e.links]
    assert len(urls) == len(set(urls))


def test_attachments_hashed_not_written():
    e = parse_file(FIX / "malware_attachment.eml")
    names = [a.filename for a in e.attachments]
    assert names == ["Invoice_2291.pdf.exe", "Statement.docm", "statements.zip", "receipt.pdf"]
    exe = e.attachments[0]
    assert exe.head.startswith(b"MZ")
    assert len(exe.sha256) == 64 and len(exe.md5) == 32


def test_form_action_extracted():
    e = parse_file(FIX / "html_smuggling.eml")
    assert any(l.text == "<form action>" for l in e.links)


def test_body_falls_back_to_stripped_html():
    raw = (b"From: a@example.com\r\nSubject: x\r\nContent-Type: text/html\r\n\r\n"
           b"<html><style>p{}</style><p>Hello <b>world</b></p><script>bad()</script></html>")
    e = parse_bytes(raw)
    assert e.body == "Hello world"


def test_extract_text_urls_strips_trailing_punctuation():
    assert extract_text_urls("go to https://a.example/x. or www.b.example!") == [
        "https://a.example/x", "www.b.example"]


def test_malformed_charset_does_not_crash():
    raw = (b"From: a@example.com\r\nSubject: x\r\nContent-Type: text/plain; charset=bogus-xyz\r\n\r\n"
           b"hello \xff\xfe")
    assert "hello" in parse_bytes(raw).body
