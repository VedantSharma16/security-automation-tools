from contextlib import contextmanager

from attack_surface_mapper import portscan


def _fake_connector(open_ports):
    @contextmanager
    def connector(address, timeout):
        host, port = address
        if port in open_ports:
            yield object()
        else:
            raise OSError("connection refused")

    return connector


def test_scan_port_true_when_connection_succeeds():
    connector = _fake_connector({80})
    assert portscan.scan_port("example.com", 80, connector=connector) is True


def test_scan_port_false_when_connection_fails():
    connector = _fake_connector({80})
    assert portscan.scan_port("example.com", 22, connector=connector) is False


def test_scan_host_returns_sorted_open_ports_with_sensitivity_flags():
    connector = _fake_connector({21, 443, 3389})
    ports = {21: "ftp", 80: "http", 443: "https", 3389: "rdp"}

    results = portscan.scan_host("example.com", ports=ports, connector=connector)

    assert [p.port for p in results] == [21, 443, 3389]
    by_port = {p.port: p for p in results}
    assert by_port[21].sensitive is True
    assert by_port[443].sensitive is False
    assert by_port[3389].sensitive is True


def test_scan_host_defaults_to_common_ports():
    connector = _fake_connector(set())
    results = portscan.scan_host("example.com", connector=connector)
    assert results == []


def test_sensitive_ports_constant_matches_scan_flags():
    connector = _fake_connector(set(portscan.COMMON_PORTS))
    results = portscan.scan_host("example.com", connector=connector)
    flagged = {p.port for p in results if p.sensitive}
    assert flagged == portscan.SENSITIVE_PORTS
