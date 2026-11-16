from pathlib import Path

import pytest

from phishlens.checks import (
    Intel,
    check_attachments,
    check_authentication,
    check_content,
    check_links,
    check_sender,
    parse_auth_results,
    run_checks,
)
from phishlens.parser import parse_bytes, parse_file

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def intel():
    return Intel.load()


def ids(findings):
    return {f.id for f in findings}


def make(headers: str, body: str = "hello", ctype: str = "text/plain") -> bytes:
    return (headers.strip() + f"\nContent-Type: {ctype}\n\n" + body).encode()


# --- authentication ---------------------------------------------------------

def test_only_first_auth_results_header_is_trusted():
    forged_second = ["mx; spf=fail; dmarc=fail", "attacker; spf=pass; dkim=pass; dmarc=pass"]
    assert parse_auth_results(forged_second) == {"spf": "fail", "dmarc": "fail"}


def test_auth_failures(intel):
    e = parse_file(FIX / "credential_phish.eml")
    found = ids(check_authentication(e, intel))
    assert {"auth.dmarc_fail", "auth.spf_fail", "auth.dkim_none"} <= found


def test_auth_missing(intel):
    e = parse_bytes(make("From: a@example.com\nSubject: hi"))
    assert ids(check_authentication(e, intel)) == {"auth.missing"}


def test_auth_all_pass_is_quiet(intel):
    e = parse_file(FIX / "benign_notification.eml")
    assert check_authentication(e, intel) == []


# --- sender -----------------------------------------------------------------

def test_bec_sender_signals(intel):
    e = parse_file(FIX / "bec_wire_fraud.eml")
    found = ids(check_sender(e, intel))
    assert "sender.display_name_spoof" in found
    assert "sender.reply_to_mismatch" in found


def test_brand_impersonation_and_lookalike_sender(intel):
    e = parse_file(FIX / "credential_phish.eml")
    found = ids(check_sender(e, intel))
    assert {"sender.brand_impersonation", "sender.lookalike_domain", "sender.reply_to_mismatch"} <= found


def test_legit_brand_sender_not_flagged(intel):
    e = parse_bytes(make('From: "PayPal" <service@paypal.com>\nReply-To: help@paypal.com\nSubject: Receipt'))
    assert check_sender(e, intel) == []


def test_extra_protected_domain_via_intel():
    intel = Intel.load(["corp-example.com"])
    e = parse_bytes(make('From: "IT" <it@corp-examp1e.com>\nSubject: x'))
    assert "sender.lookalike_domain" in ids(check_sender(e, intel))


# --- links ------------------------------------------------------------------

def test_deceptive_links(intel):
    e = parse_file(FIX / "credential_phish.eml")
    found = ids(check_links(e, intel))
    assert {"link.text_href_mismatch", "link.lookalike_domain", "link.shortener",
            "link.ip_literal", "link.cleartext_credential_path"} <= found


def test_link_findings_are_merged_not_repeated(intel):
    body = '<a href="https://bit.ly/a">a</a><a href="https://bit.ly/b">b</a>'
    e = parse_bytes(make("From: a@example.com\nSubject: x", body, "text/html"))
    fs = [f for f in check_links(e, intel) if f.id == "link.shortener"]
    assert len(fs) == 1 and len(fs[0].evidence) == 2


@pytest.mark.parametrize("href,expected", [
    ("javascript:alert(1)", "link.script_scheme"),
    ("http://www.paypal.com@203.0.113.9/login", "link.userinfo_obfuscation"),
    ("https://xn--micrsoft-qbh.com/", "link.punycode"),
    ("https://files.example.zip/doc", "link.suspicious_tld"),
])
def test_link_tricks(intel, href, expected):
    e = parse_bytes(make("From: a@example.com\nSubject: x", f'<a href="{href}">click</a>', "text/html"))
    assert expected in ids(check_links(e, intel))


def test_filename_in_link_text_is_not_a_domain_mismatch(intel):
    e = parse_bytes(make("From: a@example.com\nSubject: x",
                         '<a href="https://files.example.com/d/1">report.pdf</a>', "text/html"))
    assert "link.text_href_mismatch" not in ids(check_links(e, intel))


def test_mailto_links_ignored(intel):
    e = parse_bytes(make("From: a@example.com\nSubject: x", '<a href="mailto:x@evil.top">mail</a>', "text/html"))
    assert check_links(e, intel) == []


# --- attachments --------------------------------------------------------------

def test_attachment_detectors(intel):
    e = parse_file(FIX / "malware_attachment.eml")
    found = ids(check_attachments(e, intel))
    assert {"attachment.double_extension", "attachment.macro_enabled",
            "attachment.encrypted_archive_lure", "attachment.magic_mismatch"} <= found


def test_pe_disguised_as_pdf_is_critical(intel):
    e = parse_file(FIX / "malware_attachment.eml")
    mm = [f for f in check_attachments(e, intel) if f.id == "attachment.magic_mismatch"]
    assert mm[0].severity == "critical" and "receipt.pdf" in mm[0].evidence[0]


def test_html_attachment(intel):
    e = parse_file(FIX / "html_smuggling.eml")
    assert "attachment.html_smuggling" in ids(check_attachments(e, intel))


# --- content ----------------------------------------------------------------

def test_content_lures(intel):
    e = parse_file(FIX / "bec_wire_fraud.eml")
    found = ids(check_content(e, intel))
    assert {"content.financial_request", "content.secrecy"} <= found


def test_content_weight_is_capped(intel):
    body = " ".join(p for p in intel.lure_keywords["credential"])
    e = parse_bytes(make("From: a@example.com\nSubject: x", body))
    f = next(f for f in check_content(e, intel) if f.id == "content.credential_lure")
    assert f.weight == 30  # base 15, capped at 2x


def test_embedded_form(intel):
    e = parse_file(FIX / "html_smuggling.eml")
    assert "content.embedded_form" in ids(check_content(e, intel))


def test_run_checks_sorted_by_severity(intel):
    order = ["critical", "high", "medium", "low", "info"]
    fs = run_checks(parse_file(FIX / "credential_phish.eml"), intel)
    ranks = [order.index(f.severity) for f in fs]
    assert ranks == sorted(ranks)
