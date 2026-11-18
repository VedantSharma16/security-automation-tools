from phishscope.detectors import Finding
from phishscope.iocs import defang, defang_text, extract_iocs
from phishscope.scoring import risk_score, verdict


def _f(rule, sev):
    return Finding(rule, rule, sev, "T1566")


def test_score_and_verdict_thresholds():
    assert verdict([]) == "LIKELY_BENIGN" and risk_score([]) == 0
    assert verdict([_f("a", "LOW"), _f("b", "LOW")]) == "LIKELY_BENIGN"
    assert verdict([_f("a", "HIGH")]) == "SUSPICIOUS"
    assert verdict([_f("a", "HIGH"), _f("b", "HIGH")]) == "MALICIOUS"
    assert verdict([_f("a", "CRITICAL")]) == "MALICIOUS"


def test_repeated_rule_has_diminishing_weight():
    assert risk_score([_f("x", "LOW")] * 3) == 10  # 5 + 2.5 + 2.5
    assert risk_score([_f(str(i), "CRITICAL") for i in range(5)]) == 100


def test_defang():
    assert defang("http://evil.test/a") == "hxxp://evil[.]test/a"
    assert defang("x@evil.test") == "x[@]evil[.]test"
    assert defang_text("dmarc=fail from a@b.test") == "dmarc=fail from a[@]b[.]test"


def test_iocs_exclude_legit_brand_and_include_form_target(analyze):
    ctx, _, _ = analyze("credential_phish.eml")
    iocs = extract_iocs(ctx, defanged=False)
    assert "http://paypa1-secure.com/login/session?id=8812" in iocs["urls"]
    assert "http://185.234.219.17/collect.php" in iocs["urls"]
    assert not any("paypal.com" in u for u in iocs["urls"])
    assert "paypal.com" not in iocs["domains"]
    assert iocs["ips"] == ["185.234.219.17"]


def test_iocs_include_attachment_hashes(analyze):
    ctx, _, _ = analyze("malware_attachment.eml")
    iocs = extract_iocs(ctx)
    assert len(iocs["sha256"]) == 2 and len(iocs["md5"]) == 2
