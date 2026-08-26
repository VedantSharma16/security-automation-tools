from httpsec.models import TLSInfo
from httpsec.tls_inspector import analyze


def _ids(findings):
    return {f.id for f in findings}


def _healthy_tls_info(**overrides) -> TLSInfo:
    defaults = dict(
        protocol="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        not_before="Jan  1 00:00:00 2025 GMT",
        not_after="Jan  1 00:00:00 2030 GMT",
        days_until_expiry=365,
        subject_cn="example.com",
        issuer_cn="Some CA",
        san=["example.com", "www.example.com"],
    )
    defaults.update(overrides)
    return TLSInfo(**defaults)


def test_healthy_cert_and_modern_protocol_has_no_findings():
    info = _healthy_tls_info()
    assert analyze(info, hostname="example.com") == []


def test_deprecated_protocol_flagged():
    info = _healthy_tls_info(protocol="TLSv1.1")
    findings = analyze(info, hostname="example.com")
    assert "tls-deprecated-protocol" in _ids(findings)


def test_modern_protocol_not_flagged():
    info = _healthy_tls_info(protocol="TLSv1.2")
    findings = analyze(info, hostname="example.com")
    assert "tls-deprecated-protocol" not in _ids(findings)


def test_weak_cipher_flagged():
    info = _healthy_tls_info(cipher_name="TLS_RSA_WITH_RC4_128_SHA")
    findings = analyze(info, hostname="example.com")
    assert "tls-weak-cipher" in _ids(findings)


def test_expired_cert_is_critical():
    info = _healthy_tls_info(days_until_expiry=-5)
    findings = analyze(info, hostname="example.com")
    match = next(f for f in findings if f.id == "tls-cert-expired")
    assert match.severity == "critical"


def test_expiring_soon_is_medium():
    info = _healthy_tls_info(days_until_expiry=10)
    findings = analyze(info, hostname="example.com")
    match = next(f for f in findings if f.id == "tls-cert-expiring-soon")
    assert match.severity == "medium"


def test_expiry_well_in_future_not_flagged():
    info = _healthy_tls_info(days_until_expiry=200)
    findings = analyze(info, hostname="example.com")
    assert not any(f.id.startswith("tls-cert-expir") for f in findings)


def test_hostname_mismatch_flagged():
    info = _healthy_tls_info(subject_cn="other.example", san=["other.example"])
    findings = analyze(info, hostname="example.com")
    assert "tls-hostname-mismatch" in _ids(findings)


def test_hostname_in_san_not_flagged_even_if_cn_differs():
    info = _healthy_tls_info(subject_cn="other.example", san=["example.com"])
    findings = analyze(info, hostname="example.com")
    assert "tls-hostname-mismatch" not in _ids(findings)


def test_no_hostname_supplied_skips_mismatch_check():
    info = _healthy_tls_info(subject_cn="other.example", san=[])
    findings = analyze(info, hostname="")
    assert "tls-hostname-mismatch" not in _ids(findings)
