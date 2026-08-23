import socket

import pytest

from recon.port_scan import OpenPort, analyze_ports, scan_ports


class FakeSocket:
    def __init__(self, banner: bytes = b""):
        self._banner = banner
        self.closed = False

    def settimeout(self, timeout):
        pass

    def recv(self, n):
        if not self._banner:
            raise OSError("no banner")
        return self._banner

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def make_connector(open_ports: dict):
    def connector(host, port, timeout):
        if port in open_ports:
            return FakeSocket(open_ports[port])
        raise OSError("connection refused")

    return connector


def test_scan_ports_only_returns_open_ports():
    connector = make_connector({22: b"SSH-2.0-OpenSSH_9.0\r\n", 80: b""})
    result = scan_ports("1.2.3.4", ports=[22, 23, 80, 443], connector=connector)
    ports_found = {p.port for p in result}
    assert ports_found == {22, 80}


def test_scan_ports_captures_banner():
    connector = make_connector({22: b"SSH-2.0-OpenSSH_9.0\r\n"})
    result = scan_ports("1.2.3.4", ports=[22], connector=connector)
    assert result[0].banner == "SSH-2.0-OpenSSH_9.0"
    assert result[0].service == "ssh"


def test_scan_ports_none_open():
    connector = make_connector({})
    result = scan_ports("1.2.3.4", ports=[21, 22], connector=connector)
    assert result == []


def test_analyze_ports_no_findings_when_no_open_ports():
    assert analyze_ports("host", []) == []


def test_analyze_ports_flags_risky_port():
    open_ports = [OpenPort(port=6379, service="redis")]
    findings = analyze_ports("host", open_ports)
    risky = [f for f in findings if f.severity == "critical"]
    assert len(risky) == 1
    assert "6379" in risky[0].title


def test_analyze_ports_does_not_flag_benign_port():
    open_ports = [OpenPort(port=80, service="http")]
    findings = analyze_ports("host", open_ports)
    # Only the info-level "N open ports found" summary should appear.
    assert len(findings) == 1
    assert findings[0].severity == "info"
