from phishtriage.analyzers import run_all
from phishtriage.parser import parse_file
from phishtriage.report import build_report, defang, render_markdown
from phishtriage.scoring import assess


def report_for(path):
    email = parse_file(path)
    return build_report(email, assess(run_all(email)), source=str(path))


def test_iocs_exclude_legit_brand_urls_and_shortener_domains(fixtures_dir):
    iocs = report_for(fixtures_dir / "credential_phish.eml")["iocs"]
    assert "paypal.com.account-verify.xyz" in iocs["domains"]
    assert "paypa1.com" in iocs["domains"]
    assert "bit.ly" not in iocs["domains"]
    assert "https://bit.ly/3xPpL0g" in iocs["urls"]
    assert not any("www.paypal.com" in u for u in iocs["urls"])


def test_attachment_hashes_in_iocs(fixtures_dir):
    iocs = report_for(fixtures_dir / "malware_attachment.eml")["iocs"]
    assert {a["filename"] for a in iocs["attachments"]} == {"Invoice_8812.pdf.exe", "shipping_docs.zip"}


def test_mitre_rollup(fixtures_dir):
    r = report_for(fixtures_dir / "html_smuggling.eml")
    assert "T1027.006" in {t["id"] for t in r["mitre_attack"]}


def test_markdown_is_defanged(fixtures_dir):
    md = render_markdown(report_for(fixtures_dir / "credential_phish.eml"))
    assert "hxxp://paypal[.]com[.]account-verify[.]xyz" in md
    assert "http://paypal.com.account-verify.xyz" not in md.split("## IOCs")[1]


def test_defang():
    assert defang("https://a.b.com/x") == "hxxps://a[.]b[.]com/x"
