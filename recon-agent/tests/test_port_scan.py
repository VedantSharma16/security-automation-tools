from recon_agent.port_scan import PortResult, scan_ports


def test_scan_ports_filters_to_open_and_sorts_by_port():
    def fake_checker(host, port, timeout):
        return PortResult(port=port, open=(port in (22, 443)), service="x")

    results = scan_ports("host", ports=[443, 8080, 22], checker=fake_checker)
    assert [r.port for r in results] == [22, 443]


def test_scan_ports_empty_when_all_closed():
    def fake_checker(host, port, timeout):
        return PortResult(port=port, open=False, service="x")

    assert scan_ports("host", ports=[80, 443], checker=fake_checker) == []


def test_scan_ports_defaults_to_default_port_list(monkeypatch):
    from recon_agent import port_scan as port_scan_mod

    seen_ports = []

    def fake_checker(host, port, timeout):
        seen_ports.append(port)
        return PortResult(port=port, open=False, service="x")

    port_scan_mod.scan_ports("host", checker=fake_checker)
    assert sorted(seen_ports) == sorted(port_scan_mod.DEFAULT_PORTS)
