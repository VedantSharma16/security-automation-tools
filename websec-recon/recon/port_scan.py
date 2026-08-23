"""Threaded TCP connect-scan with lightweight banner grabbing.

A "connect scan" completes the full TCP handshake, unlike a SYN scan, which
means it doesn't need raw sockets / root privileges — the tradeoff is that
it's a little noisier and a little slower, which is an acceptable tradeoff
for an authorized, deliberately low-and-slow recon tool.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .findings import Finding

# port -> (service name, why it matters if found open on an internet-facing host)
COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3000: "dev-http",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5601: "kibana",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9000: "dev-http-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

# port -> (severity, why exposing this to the internet is risky)
_RISKY_PORTS = {
    21: ("medium", "FTP transmits credentials and data in cleartext."),
    23: ("high", "Telnet transmits credentials and all traffic in cleartext."),
    111: ("medium", "rpcbind is frequently used for reflection/enumeration attacks."),
    135: ("medium", "MSRPC exposure aids Windows host enumeration and lateral movement."),
    139: ("high", "NetBIOS/SMBv1 exposure is a common ransomware and worm entry point."),
    445: ("high", "SMB exposure is a common ransomware and worm entry point (e.g. EternalBlue)."),
    1433: ("high", "Internet-facing MSSQL is a frequent target for brute force and RCE."),
    2049: ("medium", "NFS exposure can allow unauthorized filesystem access if misconfigured."),
    2375: ("critical", "Unauthenticated Docker API exposure typically grants full remote code execution."),
    3306: ("high", "Internet-facing MySQL is a frequent target for brute force and data exfiltration."),
    3389: ("high", "RDP exposure is one of the most common initial-access ransomware vectors."),
    5432: ("high", "Internet-facing PostgreSQL is a frequent target for brute force and data exfiltration."),
    5900: ("high", "VNC is frequently deployed with weak or no authentication."),
    5984: ("high", "CouchDB has a history of unauthenticated admin-interface exposures."),
    6379: ("critical", "Redis has no authentication by default and is routinely abused for RCE/cryptomining."),
    9200: ("high", "Elasticsearch has a long history of unauthenticated data-exposure incidents."),
    27017: ("critical", "MongoDB has no authentication by default in many deployments and is a top target for data-wiping extortion."),
}


@dataclass(frozen=True)
class OpenPort:
    port: int
    service: str
    banner: str | None = None


def _default_connector(host: str, port: int, timeout: float):
    return socket.create_connection((host, port), timeout=timeout)


def _grab_banner(sock) -> str | None:
    try:
        sock.settimeout(0.5)
        data = sock.recv(128)
        return data.decode("utf-8", errors="replace").strip() or None
    except OSError:
        return None


def _probe(host: str, port: int, timeout: float, connector) -> OpenPort | None:
    try:
        sock = connector(host, port, timeout)
    except OSError:
        return None

    with sock:
        banner = _grab_banner(sock)

    return OpenPort(port=port, service=COMMON_PORTS.get(port, "unknown"), banner=banner)


def scan_ports(
    host: str,
    ports: dict[int, str] | list[int] | None = None,
    timeout: float = 1.0,
    max_workers: int = 50,
    connector=_default_connector,
) -> list[OpenPort]:
    port_list = list(ports if ports is not None else COMMON_PORTS)

    open_ports: list[OpenPort] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_port = {
            pool.submit(_probe, host, port, timeout, connector): port for port in port_list
        }
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)

    return sorted(open_ports, key=lambda p: p.port)


def analyze_ports(host: str, open_ports: list[OpenPort]) -> list[Finding]:
    findings: list[Finding] = []

    if not open_ports:
        return findings

    findings.append(
        Finding(
            category="ports",
            title=f"{len(open_ports)} open port(s) found",
            severity="info",
            description=(
                f"{host} responded to a TCP connect scan on: "
                + ", ".join(f"{p.port}/{p.service}" for p in open_ports)
            ),
            recommendation="Confirm every open port is required and internet-facing intentionally.",
            evidence={"ports": [p.port for p in open_ports]},
        )
    )

    for p in open_ports:
        risk = _RISKY_PORTS.get(p.port)
        if not risk:
            continue
        severity, reason = risk
        findings.append(
            Finding(
                category="ports",
                title=f"Port {p.port} ({p.service}) exposed",
                severity=severity,
                description=reason,
                recommendation=(
                    f"Firewall port {p.port} to trusted source IPs only, or place it "
                    "behind a VPN/bastion instead of exposing it directly."
                ),
                evidence={"port": p.port, "service": p.service, "banner": p.banner},
            )
        )

    return findings
