import dns.resolver
import pytest

from asm import dns_recon


class FakeResolver:
    """Stand-in for dns.resolver.Resolver: records is {(name, rdtype): [str] | Exception}."""

    def __init__(self, records):
        self.records = records
        self.timeout = None
        self.lifetime = None

    def resolve(self, name, rdtype):
        key = (name, rdtype)
        if key not in self.records:
            raise dns.resolver.NXDOMAIN()
        value = self.records[key]
        if isinstance(value, Exception):
            raise value
        return value


def test_resolve_records_returns_values_for_present_types():
    resolver = FakeResolver(
        {
            ("example.com", "A"): ["93.184.216.34"],
            ("example.com", "MX"): ["10 mail.example.com."],
        }
    )
    records = dns_recon.resolve_records("example.com", resolver=resolver)
    assert records["A"] == ["93.184.216.34"]
    assert records["MX"] == ["10 mail.example.com."]
    assert records["AAAA"] == []  # NXDOMAIN -> empty, not raised


def test_resolve_records_handles_timeout():
    resolver = FakeResolver({("example.com", "A"): dns.exception.Timeout()})
    records = dns_recon.resolve_records("example.com", resolver=resolver)
    assert records["A"] == []


def test_check_email_security_flags_missing_spf_and_dmarc():
    resolver = FakeResolver({})  # no _dmarc TXT record either
    findings = dns_recon.check_email_security("example.com", {"TXT": []}, resolver=resolver)
    titles = {f.title for f in findings}
    assert "No SPF record" in titles
    assert "No DMARC record" in titles


def test_check_email_security_passes_when_both_present():
    resolver = FakeResolver({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"]})
    records = {"TXT": ["v=spf1 include:_spf.example.com ~all"]}
    findings = dns_recon.check_email_security("example.com", records, resolver=resolver)
    assert findings == []


def test_build_findings_includes_info_for_each_populated_record_type():
    resolver = FakeResolver({})
    records = {"A": ["1.2.3.4"], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
    findings = dns_recon.build_findings("example.com", records, resolver=resolver)
    info_titles = {f.title for f in findings if f.severity.name == "INFO"}
    assert "A records resolved" in info_titles
    assert not any("AAAA" in t for t in info_titles)
