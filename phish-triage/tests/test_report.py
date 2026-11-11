import csv
import io

from phishtriage.analyzer import analyze_bytes
from phishtriage.report import defang, iocs_to_csv, to_markdown

from helpers import make_email


def test_defang():
    assert defang("https://evil.com/a") == "hxxps://evil[.]com/a"
    assert defang("a@b.co") == "a[@]b[.]co"


def test_iocs_extracted_and_punycode_kept_ascii():
    html = '<a href="https://xn--micrsoft-qbh.com/x">x</a><a href="mailto:a@b.c">m</a>'
    r = analyze_bytes(make_email(html=html, reply_to="r@gmail.com"))
    iocs = r["iocs"]
    assert iocs["domains"] == ["xn--micrsoft-qbh.com"]
    assert iocs["urls"] == ["https://xn--micrsoft-qbh.com/x"]
    assert iocs["sender_addresses"] == ["alice@example.org", "r@gmail.com"]
    assert iocs["originating_ip"] == "198.51.100.7"


def test_internal_originating_ip_dropped():
    raw = make_email(received="from h (h [10.1.2.3]) by mx; Mon, 09 Nov 2026 10:00:00 +0000")
    assert analyze_bytes(raw)["iocs"]["originating_ip"] is None


def test_markdown_defangs_evidence_and_lists_actions():
    r = analyze_bytes(make_email(html='<a href="http://203.0.113.5/login">Sign in</a>',
                                 auth="spf=fail; dkim=fail; dmarc=fail"))
    md = to_markdown(r)
    assert "203[.]0[.]113[.]5" in md
    assert "http://203.0.113.5" not in md
    assert "## Recommended actions" in md


def test_clean_report_actions():
    r = analyze_bytes(make_email())
    assert r["summary"]["verdict"] == "clean"
    assert r["recommended_actions"] == ["No action required. Release to user if quarantined."]


def test_csv_rows():
    r = analyze_bytes(make_email(text="go to https://evil.example/x", attachments=[("a.exe", b"MZ")]))
    rows = list(csv.DictReader(io.StringIO(iocs_to_csv([r]))))
    types = {row["type"] for row in rows}
    assert {"email", "ipv4", "domain", "url", "sha256"} <= types
    assert all(row["verdict"] == r["summary"]["verdict"] for row in rows)
