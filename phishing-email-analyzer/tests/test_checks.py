from helpers import make_email

from phishscope.checks import (
    AnalysisConfig,
    analyze_link,
    check_attachments,
    check_authentication,
    check_content,
    check_display_name,
    check_links,
    check_sender_mismatch,
    normalize_url,
    run_all_checks,
)
from phishscope.parser import Link

CFG = AnalysisConfig()


def ids(findings):
    return {f.check for f in findings}


# ---- authentication


def test_dmarc_fail_is_high():
    f = check_authentication(make_email(auth="spf=fail; dkim=fail; dmarc=fail"), CFG)
    assert "dmarc_fail" in ids(f)
    assert next(x for x in f if x.check == "dmarc_fail").severity == "high"


def test_all_pass_produces_nothing():
    assert check_authentication(make_email(), CFG) == []


def test_missing_auth_results_is_low():
    f = check_authentication(make_email(auth=None), CFG)
    assert ids(f) == {"auth_missing"} and f[0].severity == "low"


# ---- sender


def test_reply_to_to_freemail_is_high():
    f = check_sender_mismatch(make_email(reply_to="ceo.private@gmail.com"), CFG)
    hit = next(x for x in f if x.check == "reply_to_mismatch")
    assert hit.severity == "high"


def test_reply_to_same_org_subdomain_is_fine():
    assert check_sender_mismatch(make_email(reply_to="support@help.example.org"), CFG) == []


def test_display_name_brand_spoof():
    f = check_display_name(make_email(frm='"PayPal Service" <service@pp-billing.net>'), CFG)
    assert "display_name_brand_spoof" in ids(f)


def test_display_name_brand_from_real_domain_is_fine():
    assert check_display_name(make_email(frm='"PayPal" <service@paypal.com>'), CFG) == []


def test_display_name_containing_other_address():
    f = check_display_name(make_email(frm='"ceo@acme-corp.com" <x@mailer.example>'), CFG)
    assert "display_name_address_spoof" in ids(f)


# ---- links


def test_normalize_url_refangs():
    assert normalize_url("hxxps://evil[.]example[.]com/x") == "https://evil.example.com/x"


def test_anchor_text_mismatch_is_deceptive():
    reasons = analyze_link(Link("https://evil.example/login", "www.paypal.com", "html"), CFG)
    assert any("anchor text" in r for r in reasons)


def test_matching_anchor_text_is_clean():
    assert analyze_link(Link("https://www.paypal.com/signin", "paypal.com", "html"), CFG) == []


def test_userinfo_trick():
    reasons = analyze_link(Link("https://paypal.com@evil.example/login"), CFG)
    assert any("userinfo" in r for r in reasons)


def test_javascript_scheme():
    assert analyze_link(Link("javascript:alert(1)", "click", "html"), CFG)


def test_direct_executable_download():
    reasons = analyze_link(Link("https://files.example.net/update.exe"), CFG)
    assert any(".exe" in r for r in reasons)


def test_mailto_and_relative_links_are_ignored():
    assert analyze_link(Link("mailto:help@example.org"), CFG) == []
    assert analyze_link(Link("/unsubscribe"), CFG) == []


def test_embedded_form_is_critical():
    e = make_email(html='<form action="https://collector.example/p"><input type=password></form>')
    f = check_links(e, CFG)
    assert f and f[0].severity == "critical"


# ---- attachments


def test_double_extension_executable():
    f = check_attachments(make_email(attachments=[("invoice.pdf.exe", b"MZ" + b"\0" * 10)]), CFG)
    assert "attachment_double_extension" in ids(f)


def test_pe_content_behind_document_name():
    f = check_attachments(make_email(attachments=[("report.pdf", b"MZ\x90\x00rest")]), CFG)
    assert "attachment_magic_mismatch" in ids(f)
    assert any(x.severity == "critical" for x in f)


def test_iso_and_macro_documents_flagged():
    f = check_attachments(make_email(attachments=[("x.iso", b"\0" * 8), ("q.xlsm", b"PK\x03\x04")]), CFG)
    assert {"attachment_container", "attachment_macro"} <= ids(f)


def test_valid_pdf_is_clean():
    assert check_attachments(make_email(attachments=[("terms.pdf", b"%PDF-1.7")]), CFG) == []


# ---- content


def test_credential_and_urgency_language():
    e = make_email(subject="Action required", body="Verify your account immediately or it will be suspended.")
    assert {"credential_lure", "urgency_pressure"} <= ids(check_content(e, CFG))


def test_bec_language_escalates_with_reply_to_redirect():
    body = "Are you available? I need a wire transfer processed. Keep this confidential."
    plain = check_content(make_email(body=body), CFG)
    redirected = check_content(make_email(body=body, reply_to="boss@gmail.com"), CFG)
    assert next(f for f in plain if f.check == "bec_payment_lure").severity == "medium"
    assert next(f for f in redirected if f.check == "bec_payment_lure").severity == "high"


def test_benign_email_has_no_findings():
    assert run_all_checks(make_email(body="Lunch on Friday? Menu: https://example.org/menu")) == []


def test_findings_sorted_most_severe_first():
    e = make_email(
        auth="spf=fail; dkim=fail; dmarc=fail",
        attachments=[("a.pdf.exe", b"MZ")],
    )
    sev = [f.severity for f in run_all_checks(e)]
    assert sev[0] == "critical"
