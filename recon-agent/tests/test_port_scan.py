from recon_agent.port_scan import scan_ports


class FakeSocket:
    def __init__(self, banner: bytes = b""):
        self._banner = banner
        self.closed = False

    def settimeout(self, timeout):
        pass

    def recv(self, size):
        return self._banner

    def close(self):
        self.closed = True


def test_scan_ports_reports_only_open_ports():
    def connector(address, timeout):
        ip, port = address
        if port in (22, 80):
            return FakeSocket()
        raise OSError("connection refused")

    results = scan_ports("10.0.0.1", ports=[22, 80, 443, 3389], connector=connector)
    open_ports = sorted(r.port for r in results)
    assert open_ports == [22, 80]


def test_scan_ports_captures_banner():
    def connector(address, timeout):
        return FakeSocket(banner=b"SSH-2.0-OpenSSH_8.9\r\n")

    results = scan_ports("10.0.0.1", ports=[22], connector=connector)
    assert len(results) == 1
    assert results[0].banner == "SSH-2.0-OpenSSH_8.9"


def test_scan_ports_handles_no_banner_gracefully():
    class SilentSocket(FakeSocket):
        def recv(self, size):
            raise OSError("timed out")

    def connector(address, timeout):
        return SilentSocket()

    results = scan_ports("10.0.0.1", ports=[443], connector=connector)
    assert results[0].open is True
    assert results[0].banner is None


def test_scan_ports_returns_sorted_results():
    def connector(address, timeout):
        return FakeSocket()

    results = scan_ports("10.0.0.1", ports=[443, 22, 80], connector=connector)
    assert [r.port for r in results] == [22, 80, 443]
