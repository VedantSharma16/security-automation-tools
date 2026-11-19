from helpers import FIXTURES, make_email

from phishscope.parser import domain_of, parse_file


def test_parses_headers_and_auth_results():
    e = parse_file(FIXTURES / "credential_phish.eml")
    assert e.from_address == "no-reply@micros0ft-support.com"
    assert e.from_display == "Microsoft 365 Security"
    assert e.from_domain == "micros0ft-support.com"
    assert e.return_path == "bounce@mailer-77.top"
    assert (e.auth.spf, e.auth.dkim, e.auth.dmarc) == ("softfail", "none", "fail")


def test_extracts_html_anchor_text_and_href_separately():
    e = parse_file(FIXTURES / "credential_phish.eml")
    deceptive = [l for l in e.links if l.text == "https://login.microsoftonline.com"]
    assert deceptive and deceptive[0].url.startswith("http://login.micros0ft-support.xyz")


def test_anchor_text_urls_are_not_treated_as_links():
    e = parse_file(FIXTURES / "credential_phish.eml")
    assert not any(l.url == "https://login.microsoftonline.com" for l in e.links)


def test_extracts_form_actions():
    e = parse_file(FIXTURES / "credential_phish.eml")
    assert any(l.text == "<form action>" and "203.0.113.45" in l.url for l in e.links)


def test_hashes_attachments_and_captures_magic_bytes():
    e = parse_file(FIXTURES / "malware_attachment.eml")
    names = [a.filename for a in e.attachments]
    assert names == ["Invoice_4471.pdf.exe", "remittance_advice.html", "terms.pdf"]
    exe = e.attachments[0]
    assert exe.head.startswith(b"MZ")
    assert len(exe.sha256) == 64


def test_first_authentication_results_header_wins():
    # A sender can inject its own Authentication-Results lower in the headers;
    # only the receiving MTA's (top-most) verdict should be trusted.
    from email.message import EmailMessage

    from phishscope.parser import parse_bytes

    m = EmailMessage()
    m["Authentication-Results"] = "mx.real; dmarc=fail"
    m["Authentication-Results"] = "forged; dmarc=pass"
    m["From"] = "x@y.com"
    m.set_content("hi")
    assert parse_bytes(bytes(m)).auth.dmarc == "fail"


def test_plain_text_urls_are_extracted():
    e = make_email(body="see https://example.org/a and hxxp://evil.example/b")
    urls = {l.url for l in e.links}
    assert {"https://example.org/a", "hxxp://evil.example/b"} <= urls


def test_domain_of():
    assert domain_of("Bob <BOB@Example.COM>") == "example.com"
    assert domain_of("not-an-address") == ""
