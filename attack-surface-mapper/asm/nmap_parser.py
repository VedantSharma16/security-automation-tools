"""Parse nmap XML scan output (`nmap -oX`) into structured Host/Port records.

Only the fields the rest of the pipeline needs are extracted: address,
hostname, and per-port protocol/state/service/product/version. Anything
else in the XML (scripts, timing stats, OS guesses) is ignored.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Port:
    port_id: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    def display_name(self) -> str:
        """Best-available human label for this service, e.g. 'OpenSSH 7.2p2'."""
        if self.product and self.version:
            return f"{self.product} {self.version}"
        return self.product or self.service or f"port {self.port_id}"


@dataclass
class Host:
    address: str
    hostname: str = ""
    ports: list[Port] = field(default_factory=list)

    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.is_open]


def _parse_host(host_el: ET.Element) -> Host | None:
    addr_el = host_el.find("address")
    if addr_el is None:
        return None
    address = addr_el.get("addr", "")

    hostname = ""
    hostnames_el = host_el.find("hostnames/hostname")
    if hostnames_el is not None:
        hostname = hostnames_el.get("name", "")

    ports: list[Port] = []
    for port_el in host_el.findall("ports/port"):
        state_el = port_el.find("state")
        service_el = port_el.find("service")
        try:
            port_id = int(port_el.get("portid", "-1"))
        except ValueError:
            continue
        if port_id < 0:
            continue

        ports.append(
            Port(
                port_id=port_id,
                protocol=port_el.get("protocol", "tcp"),
                state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                service=service_el.get("name", "") if service_el is not None else "",
                product=service_el.get("product", "") if service_el is not None else "",
                version=service_el.get("version", "") if service_el is not None else "",
                extrainfo=service_el.get("extrainfo", "") if service_el is not None else "",
            )
        )

    return Host(address=address, hostname=hostname, ports=ports)


def parse_string(xml_text: str) -> list[Host]:
    """Parse an in-memory nmap XML document into a list of Host records."""
    root = ET.fromstring(xml_text)
    hosts: list[Host] = []
    for host_el in root.findall("host"):
        host = _parse_host(host_el)
        if host is not None:
            hosts.append(host)
    return hosts


def parse_file(path: str | Path) -> list[Host]:
    """Parse an nmap XML file (`nmap -oX scan.xml`) into a list of Host records."""
    return parse_string(Path(path).read_text(encoding="utf-8"))
