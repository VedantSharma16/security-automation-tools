from recon_agent.tools import (
    grab_banner,
    http_headers,
    parse_banner,
    tcp_connect_scan,
    tls_cert_info,
)


def test_tcp_connect_scan_reports_open_and_closed_ports(ssh_banner_server, closed_port):
    result = tcp_connect_scan("127.0.0.1", ports=[ssh_banner_server.port, closed_port])
    assert result["open_ports"] == [ssh_banner_server.port]
    assert closed_port not in result["open_ports"]
    assert result["ports_scanned"] == [ssh_banner_server.port, closed_port]


def test_tcp_connect_scan_unresolvable_host_returns_no_open_ports():
    result = tcp_connect_scan("this-host-does-not-resolve.invalid", ports=[80])
    assert result["open_ports"] == []


def test_grab_banner_parses_known_service(ssh_banner_server):
    result = grab_banner("127.0.0.1", ssh_banner_server.port)
    assert result["service"] == "OpenSSH"
    assert result["version"] == "7.2"
    assert "SSH-2.0-OpenSSH_7.2" in result["banner"]
    assert result["error"] is None


def test_grab_banner_handles_silent_service(silent_server):
    result = grab_banner("127.0.0.1", silent_server.port)
    assert result["banner"] == ""
    assert result["service"] is None
    assert result["version"] is None


def test_grab_banner_reports_connection_error(closed_port):
    result = grab_banner("127.0.0.1", closed_port)
    assert result["error"] is not None
    assert result["service"] is None


def test_parse_banner_recognizes_vsftpd():
    service, version = parse_banner("220 (vsFTPd 2.3.4)")
    assert service == "vsftpd"
    assert version == "2.3.4"


def test_parse_banner_unknown_returns_none():
    service, version = parse_banner("hello there")
    assert service is None
    assert version is None


def test_http_headers_parses_status_and_server(http_server):
    result = http_headers("127.0.0.1", http_server.port)
    assert result["status_line"] == "HTTP/1.1 200 OK"
    assert result["headers"]["Server"] == "Apache/2.4.49 (Unix)"
    assert result["service"] == "Apache"
    assert result["version"] == "2.4.49"
    assert result["error"] is None


def test_http_headers_reports_connection_error(closed_port):
    result = http_headers("127.0.0.1", closed_port)
    assert result["error"] is not None
    assert result["status_line"] is None


def test_tls_cert_info_over_tls(tls_server):
    result = tls_cert_info("127.0.0.1", tls_server.port)
    assert result["error"] is None
    assert result["protocol"] is not None
    assert result["subject"] is not None
    assert "127.0.0.1" in result["subject"]
    assert result["days_until_expiry"] is not None
    assert result["days_until_expiry"] > 0


def test_tls_cert_info_reports_connection_error(closed_port):
    result = tls_cert_info("127.0.0.1", closed_port)
    assert result["error"] is not None
