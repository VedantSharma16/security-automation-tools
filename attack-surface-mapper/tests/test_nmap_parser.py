from pathlib import Path

from asm.nmap_parser import parse_file, parse_string

EXAMPLES = Path(__file__).parent.parent / "examples"

MINIMAL_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="test.example" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed"/>
        <service name="unknown"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_string_extracts_host_and_ports():
    hosts = parse_string(MINIMAL_XML)
    assert len(hosts) == 1

    host = hosts[0]
    assert host.address == "192.0.2.10"
    assert host.hostname == "test.example"
    assert len(host.ports) == 2


def test_open_ports_filters_closed_states():
    hosts = parse_string(MINIMAL_XML)
    open_ports = hosts[0].open_ports()
    assert len(open_ports) == 1
    assert open_ports[0].port_id == 22


def test_port_display_name_prefers_product_and_version():
    hosts = parse_string(MINIMAL_XML)
    ssh_port = hosts[0].open_ports()[0]
    assert ssh_port.display_name() == "OpenSSH 8.9p1"


def test_parse_file_reads_sample_scan():
    hosts = parse_file(EXAMPLES / "sample_scan.xml")
    assert len(hosts) == 2
    addresses = {h.address for h in hosts}
    assert addresses == {"10.10.10.5", "10.10.10.6"}


def test_parse_string_with_no_hosts_returns_empty_list():
    assert parse_string("<nmaprun></nmaprun>") == []


def test_parse_string_skips_host_without_address():
    xml = """<nmaprun><host><ports/></host></nmaprun>"""
    assert parse_string(xml) == []
