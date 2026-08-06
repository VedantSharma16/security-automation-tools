from recon_agent.tools import dns_tool


def fake_query(records):
    def _query(domain: str, rtype: str):
        if domain.startswith("_dmarc."):
            return records.get("DMARC", [])
        return records.get(rtype, [])

    return _query


def test_analyze_records_flags_missing_resolution():
    findings = dns_tool.analyze_records("nowhere.example", {"A": [], "AAAA": []})
    titles = [f.title for f in findings]
    assert "No resolvable A/AAAA records" in titles


def test_analyze_records_flags_missing_spf_and_dmarc():
    records = {"A": ["93.184.216.34"], "TXT": [], "DMARC": [], "NS": ["ns1.example.com", "ns2.example.com"]}
    findings = dns_tool.analyze_records("example.com", records)
    titles = {f.title for f in findings}
    assert "No SPF record found" in titles
    assert "No DMARC record found" in titles
    assert "Single authoritative nameserver" not in titles


def test_analyze_records_clean_when_spf_dmarc_and_multiple_ns_present():
    records = {
        "A": ["93.184.216.34"],
        "TXT": ["v=spf1 include:_spf.example.com ~all"],
        "DMARC": ["v=DMARC1; p=reject"],
        "NS": ["ns1.example.com", "ns2.example.com"],
    }
    findings = dns_tool.analyze_records("example.com", records)
    assert findings == []


def test_analyze_records_flags_single_nameserver():
    records = {
        "A": ["93.184.216.34"],
        "TXT": ["v=spf1 -all"],
        "DMARC": ["v=DMARC1; p=reject"],
        "NS": ["ns1.example.com"],
    }
    findings = dns_tool.analyze_records("example.com", records)
    titles = {f.title for f in findings}
    assert "Single authoritative nameserver" in titles


def test_run_wires_query_fn_through_and_includes_dmarc():
    records = {
        "A": ["93.184.216.34"],
        "TXT": ["v=spf1 -all"],
        "DMARC": ["v=DMARC1; p=reject"],
        "NS": ["ns1.example.com", "ns2.example.com"],
    }
    result = dns_tool.run("example.com", query_fn=fake_query(records))
    assert result.tool == "dns"
    assert result.data["A"] == ["93.184.216.34"]
    assert result.data["DMARC"] == ["v=DMARC1; p=reject"]
    assert result.findings == []


def test_run_tolerates_query_fn_exceptions():
    def broken_query(domain, rtype):
        raise RuntimeError("resolver timeout")

    result = dns_tool.run("example.com", query_fn=broken_query)
    assert result.data["A"] == []
    assert result.data["DMARC"] == []
