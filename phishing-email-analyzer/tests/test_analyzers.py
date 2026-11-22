from helpers import make_email

from phishtriage.analyzers import (
    analyze_attachments,
    analyze_authentication,
    analyze_content,
    analyze_sender,
    analyze_urls,
)


def ids(indicators):
    return {i.id for i in indicators}


# ---- authentication
def test_auth_failures_are_flagged():
    found = analyze_authentication(make_email(auth="spf=fail; dkim=fail; dmarc=fail"))
    assert {"spf_fail", "dkim_fail", "dmarc_fail"} <= ids(found)


def test_missing_auth_results_is_informational():
    found = analyze_authentication(make_email(auth=None))
    assert ids(found) == {"auth_results_missing"} and found[0].severity == "info"


# ---- sender
def test_display_name_brand_spoof():
    found = analyze_sender(make_email(from_='"Microsoft 365 Support" <it@helpdesk-mail.net>'))
    assert "display_name_brand_spoof" in ids(found)


def test_real_brand_domain_is_not_brand_spoof():
    assert analyze_sender(make_email(from_='"Microsoft" <account-security@microsoft.com>')) == []


def test_display_name_embedding_other_address():
    found = analyze_sender(make_email(from_='"ceo@corp.com" <x@attacker.example>'))
    assert "display_name_embedded_address" in ids(found)


def test_reply_to_to_freemail_is_high():
    found = analyze_sender(make_email(reply_to="boss@gmail.com"))
    hit = next(i for i in found if i.id == "reply_to_mismatch")
    assert hit.severity == "high"


def test_reply_to_same_org_subdomain_is_fine():
    assert analyze_sender(make_email(reply_to="support@help.example.com")) == []


# ---- urls
def test_anchor_text_mismatch():
    html = '<a href="https://evil.example/login">https://www.mybank.com</a>'
    found = analyze_urls(make_email(html=html))
    assert "url_text_mismatch" in ids(found)


def test_matching_anchor_text_is_fine():
    html = '<a href="https://www.example.com/a">www.example.com</a>'
    assert analyze_urls(make_email(html=html, text="")) == []


def test_ip_userinfo_and_script_urls():
    html = ('<a href="http://192.0.2.10/x">a</a>'
            '<a href="https://www.paypal.com@evil.example/">b</a>'
            '<a href="javascript:alert(1)">c</a>')
    found = ids(analyze_urls(make_email(html=html, text="")))
    assert {"url_ip_host", "url_userinfo_obfuscation", "url_script_scheme"} <= found


def test_free_hosting_tld_and_shortener():
    text = "https://login-portal.web.app/ https://promo.click/ https://bit.ly/abc"
    found = ids(analyze_urls(make_email(text=text)))
    assert {"url_free_hosting", "url_suspicious_tld", "url_shortener"} <= found


def test_mailto_links_are_ignored():
    assert analyze_urls(make_email(html='<a href="mailto:x@y.com">mail us</a>', text="")) == []


# ---- attachments
def test_double_extension_and_rlo():
    found = analyze_attachments(make_email(attachments=[
        ("report.pdf.exe", b"MZ\x90\x00", ("application", "octet-stream")),
        ("invoice‮fdp.scr", b"MZ\x90\x00", ("application", "octet-stream")),
    ]))
    assert {"attachment_double_extension", "attachment_rlo"} <= ids(found)


def test_magic_byte_mismatch_executable_named_pdf():
    found = analyze_attachments(make_email(attachments=[
        ("statement.pdf", b"MZ\x90\x00rest", ("application", "pdf"))]))
    hit = next(i for i in found if i.id == "attachment_magic_mismatch")
    assert hit.severity == "critical"


def test_real_pdf_is_clean():
    found = analyze_attachments(make_email(attachments=[
        ("statement.pdf", b"%PDF-1.7\n...", ("application", "pdf"))]))
    assert found == []


def test_password_protected_archive_is_escalated():
    found = analyze_attachments(make_email(text="The password is 1234", attachments=[
        ("docs.zip", b"PK\x03\x04", ("application", "zip"))]))
    assert next(i for i in found if i.id == "attachment_archive").severity == "medium"


def test_html_attachment_variants():
    smuggle = b'<script>var b=new Blob([atob("QQ==")]);URL.createObjectURL(b)</script>'
    form = b'<form action="x"><input type="password"></form>'
    found = analyze_attachments(make_email(attachments=[
        ("a.html", smuggle, ("text", "html")),
        ("b.htm", form, ("text", "html")),
        ("c.svg", b"<svg></svg>", ("image", "svg+xml")),
    ]))
    assert {"attachment_html_smuggling", "attachment_credential_form", "attachment_html"} <= ids(found)


def test_macro_document():
    found = analyze_attachments(make_email(attachments=[
        ("Q3.xlsm", b"PK\x03\x04", ("application", "vnd.ms-excel.sheet.macroEnabled.12"))]))
    assert next(i for i in found if i.id == "attachment_macro_capable").severity == "high"


# ---- content
def test_content_lures():
    email = make_email(
        subject="URGENT action required",
        text="Verify your account immediately: https://x.example/login. Wire transfer today, "
             "updated banking details attached.")
    found = ids(analyze_content(email))
    assert {"content_urgency", "content_credential_request", "content_bec_language"} <= found


def test_credential_words_without_links_are_not_a_credential_request():
    assert "content_credential_request" not in ids(analyze_content(make_email(text="Reset your password at the kiosk.")))
