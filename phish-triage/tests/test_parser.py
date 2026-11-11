from phishtriage.parser import parse_bytes

from helpers import make_email, make_zip


def test_basic_headers_and_auth():
    raw = make_email(from_='"PayPal" <service@paypa1.com>', reply_to="x@gmail.com",
                     return_path="<bounce@mailer.net>",
                     auth="spf=fail smtp.mailfrom=paypa1.com; dkim=none; dmarc=fail")
    e = parse_bytes(raw)
    assert e.from_name == "PayPal"
    assert e.from_address == "service@paypa1.com"
    assert e.from_domain == "paypa1.com"
    assert e.reply_to_domain == "gmail.com"
    assert e.return_path_domain == "mailer.net"
    assert (e.auth.spf, e.auth.dkim, e.auth.dmarc) == ("fail", "none", "fail")


def test_received_hop_ip_and_timestamp():
    e = parse_bytes(make_email())
    assert e.received[0].ip == "198.51.100.7"
    assert e.received[0].from_host == "mail.example.org"
    assert e.received[0].timestamp.startswith("2026-11-09T10:00:00")
    assert e.originating_ip == "198.51.100.7"


def test_received_spf_fallback():
    raw = b"Received-SPF: softfail (domain does not designate)\r\nFrom: a@b.com\r\n\r\nbody\r\n"
    assert parse_bytes(raw).auth.spf == "softfail"


def test_links_from_html_text_and_forms():
    html = ('<a href="https://evil.example/x">https://bank.com</a>'
            '<form action="https://evil.example/post"></form>')
    e = parse_bytes(make_email(text="see https://plain.example/page.", html=html))
    by_source = {(link.source, link.href, link.text) for link in e.links}
    assert ("html", "https://evil.example/x", "https://bank.com") in by_source
    assert ("form", "https://evil.example/post", "") in by_source
    assert ("text", "https://plain.example/page", "") in by_source  # trailing '.' stripped


def test_hidden_text_is_separated_from_visible_text():
    html = '<p>Visible</p><div style="display: none">secret <b>nested</b></div><p>after</p>'
    e = parse_bytes(make_email(text="", html=html))
    assert e.hidden_text == "secret nested"
    assert "secret" not in e.visible_text
    assert "after" in e.visible_text


def test_font_size_not_zero_is_not_hidden():
    e = parse_bytes(make_email(html='<span style="font-size:0.9em">small</span>'))
    assert e.hidden_text == ""


def test_attachments_hashed():
    payload = make_zip({"a.txt": b"x"})
    e = parse_bytes(make_email(attachments=[("a.zip", payload)]))
    att = e.attachments[0]
    assert att.filename == "a.zip"
    assert att.size == len(payload)
    assert len(att.sha256) == 64 and len(att.md5) == 32


def test_malformed_email_does_not_crash():
    e = parse_bytes(b"this is not really an email")
    assert e.from_address == "" and e.links == [] and e.attachments == []
