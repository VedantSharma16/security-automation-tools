import json

from recon_assistant import cli
from recon_assistant.authorization import AuthorizationError
from recon_assistant.scanner import PortResult


def test_public_target_without_confirmation_exits_error(monkeypatch, capsys):
    monkeypatch.setattr(cli.socket, "gethostbyname", lambda host: "93.184.216.34")
    code = cli.main(["example.com", "--ports", "22"])
    assert code == cli.EXIT_ERROR
    assert "Refusing to scan" in capsys.readouterr().err


def test_full_run_against_fake_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.socket, "gethostbyname", lambda host: "10.0.0.5")
    monkeypatch.setattr(
        cli,
        "scan_ports",
        lambda ip, ports, **kw: [
            PortResult(port=22, open=True, banner="SSH-2.0-OpenSSH_9.6"),
            PortResult(port=6379, open=True, banner=""),
            PortResult(port=80, open=False),
        ],
    )
    monkeypatch.setattr(cli.http_audit, "audit_open_ports", lambda host, ports, **kw: [])

    out_path = tmp_path / "report.json"
    code = cli.main(
        [
            "internal.example",
            "--ports",
            "22,80,6379",
            "--format",
            "json",
            "--out",
            str(out_path),
        ]
    )

    assert code == cli.EXIT_FINDINGS  # Redis on 6379 triggers a finding
    report = json.loads(out_path.read_text())
    assert report["resolved_ip"] == "10.0.0.5"
    assert any(f["type"] == "exposed_database" for f in report["findings"])
    assert "narrative" in report


def test_clean_scan_exits_zero(monkeypatch):
    monkeypatch.setattr(cli.socket, "gethostbyname", lambda host: "127.0.0.1")
    monkeypatch.setattr(cli, "scan_ports", lambda ip, ports, **kw: [PortResult(port=22, open=False)])
    monkeypatch.setattr(cli.http_audit, "audit_open_ports", lambda host, ports, **kw: [])

    code = cli.main(["localhost", "--ports", "22"])
    assert code == cli.EXIT_CLEAN


def test_unresolvable_host_exits_error(monkeypatch, capsys):
    import socket

    def raise_gaierror(host):
        raise socket.gaierror("not found")

    monkeypatch.setattr(cli.socket, "gethostbyname", raise_gaierror)
    code = cli.main(["nope.invalid", "--ports", "22"])
    assert code == cli.EXIT_ERROR
    assert "could not resolve" in capsys.readouterr().err
