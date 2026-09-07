from recon_assistant.fingerprint import fingerprint_port


def test_telnet_flagged_by_port():
    findings = fingerprint_port(23, "")
    assert any(f.type == "cleartext_protocol" and f.severity == "high" for f in findings)


def test_ftp_flagged_by_port():
    findings = fingerprint_port(21, "220 ProFTPD ready")
    assert any(f.type == "cleartext_protocol" and f.severity == "medium" for f in findings)


def test_outdated_openssh_flagged():
    findings = fingerprint_port(22, "SSH-2.0-OpenSSH_6.6p1 Ubuntu")
    assert any(f.type == "outdated_service" for f in findings)


def test_modern_openssh_not_flagged_as_outdated():
    findings = fingerprint_port(22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu")
    assert not any(f.type == "outdated_service" for f in findings)


def test_exposed_database_flagged():
    findings = fingerprint_port(6379, "")
    assert any(f.type == "exposed_database" and "Redis" in f.title for f in findings)


def test_smb_flagged():
    findings = fingerprint_port(445, "")
    assert any(f.type == "exposed_admin_surface" and f.severity == "high" for f in findings)


def test_rdp_flagged():
    findings = fingerprint_port(3389, "")
    assert any(f.type == "exposed_admin_surface" and f.severity == "medium" for f in findings)


def test_benign_port_produces_no_findings():
    findings = fingerprint_port(12345, "some harmless custom banner")
    assert findings == []


def test_finding_to_dict_has_expected_keys():
    finding = fingerprint_port(23, "")[0]
    d = finding.to_dict()
    assert set(d) == {"type", "severity", "port", "title", "detail", "recommendation"}
