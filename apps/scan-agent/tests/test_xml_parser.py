"""XML parsing, against real nmap 7.99 output and against hostile edge cases."""

from __future__ import annotations

import pytest

from threatsculpt_agent.errors import XmlParseError
from threatsculpt_agent.nmap.xml_parser import parse_nmap_xml

# --- real captured output -----------------------------------------------------------


def test_parses_a_real_service_scan(service_xml: bytes) -> None:
    scan = parse_nmap_xml(service_xml)

    assert scan.nmap_version == "7.99"
    assert scan.hosts_up == 1
    host = scan.hosts[0]
    assert host.ip == "127.0.0.1"
    assert host.hostname == "localhost"
    assert host.state == "up"


def test_extracts_service_product_version_and_cpe_from_real_output(service_xml: bytes) -> None:
    """The listener started by regenerate.sh, as nmap actually fingerprinted it."""
    host = parse_nmap_xml(service_xml).hosts[0]
    http = next(port for port in host.ports if port.port == 8080)

    assert http.protocol == "tcp"
    assert http.state == "open"
    assert http.service == "http"
    assert http.product == "SimpleHTTPServer"
    assert http.version == "0.6"
    assert http.cpes == ("cpe:/a:python:simplehttpserver:0.6",)


def test_takes_the_highest_accuracy_os_match(service_xml: bytes) -> None:
    os_observation = parse_nmap_xml(service_xml).hosts[0].os
    assert os_observation is not None
    assert os_observation.family == "Linux"
    assert os_observation.accuracy == 97
    assert os_observation.version is not None


def test_closed_ports_are_not_submitted_by_default(closed_ports_xml: bytes) -> None:
    """Real output that lists closed ports individually; submitting them is pure noise."""
    default_ports = parse_nmap_xml(closed_ports_xml).hosts[0].ports
    every_port = parse_nmap_xml(closed_ports_xml, include_port_states=None).hosts[0].ports

    assert all(port.state in {"open", "open|filtered"} for port in default_ports)
    assert len(every_port) > len(default_ports)
    assert any(port.state == "closed" for port in every_port)


def test_collapsed_extraports_are_not_mistaken_for_ports(service_xml: bytes) -> None:
    """With ~1000 ports nmap emits <extraports count="999"/> instead of 999 elements.

    It is a summary, not an observation, and must not become 999 phantom port rows.
    """
    assert b'<extraports state="closed" count="999"' in service_xml
    assert len(parse_nmap_xml(service_xml, include_port_states=None).hosts[0].ports) == 1


def test_parses_a_real_discovery_scan(discovery_xml: bytes) -> None:
    scan = parse_nmap_xml(discovery_xml)
    assert scan.hosts_up == 1
    assert scan.hosts[0].ip == "127.0.0.1"
    assert scan.hosts[0].ports == ()


def test_timestamps_come_from_the_scan_not_the_clock(service_xml: bytes) -> None:
    scan = parse_nmap_xml(service_xml)
    assert scan.started_at <= scan.finished_at
    assert scan.started_at.tzinfo is not None


def test_no_cve_or_severity_is_ever_produced(service_xml: bytes) -> None:
    """Enrichment is server-side; the agent must not invent findings."""
    payload = parse_nmap_xml(service_xml).model_dump_json().lower()
    for forbidden in ("cve", "severity", "cvss", "risk"):
        assert forbidden not in payload


# --- synthetic edge cases ------------------------------------------------------------

MULTI_HOST = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.99" start="1786572695">
<host><status state="up"/><address addr="10.0.4.12" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Acme"/>
<hostnames><hostname name="user" type="user"/><hostname name="db01.corp.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.18.0"><cpe>cpe:/a:nginx:nginx:1.18.0</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
</ports>
<os><osmatch name="Linux 4.x" accuracy="90"><osclass osfamily="Linux" osgen="4.X" accuracy="90"/></osmatch>
<osmatch name="Linux 5.x" accuracy="96"><osclass osfamily="Linux" osgen="5.X" accuracy="96"/></osmatch></os>
</host>
<host><status state="down"/><address addr="10.0.4.13" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="2001:db8::1" addrtype="ipv6"/></host>
<runstats><finished time="1786572700"/><hosts up="2" down="1" total="3"/></runstats>
</nmaprun>"""


def test_ports_belong_to_exactly_one_host() -> None:
    """v1 accumulated ports into one shared list, so host #2 inherited host #1's ports."""
    scan = parse_nmap_xml(MULTI_HOST)
    by_ip = {host.ip: host for host in scan.hosts}

    assert len(by_ip["10.0.4.12"].ports) == 1
    assert by_ip["2001:db8::1"].ports == ()


def test_down_hosts_are_excluded_by_default() -> None:
    scan = parse_nmap_xml(MULTI_HOST)
    assert {host.ip for host in scan.hosts} == {"10.0.4.12", "2001:db8::1"}
    assert scan.hosts_total == 3

    with_down = parse_nmap_xml(MULTI_HOST, include_down_hosts=True)
    assert len(with_down.hosts) == 3
    assert with_down.hosts_up == 2


def test_mac_and_ptr_hostname_are_extracted() -> None:
    host = next(h for h in parse_nmap_xml(MULTI_HOST).hosts if h.ip == "10.0.4.12")
    assert host.mac == "00:11:22:33:44:55"
    assert host.hostname == "db01.corp.local"  # the PTR name, not the "user" one


def test_multiple_cpes_are_all_kept() -> None:
    host = next(h for h in parse_nmap_xml(MULTI_HOST).hosts if h.ip == "10.0.4.12")
    assert host.ports[0].cpes == ("cpe:/a:nginx:nginx:1.18.0", "cpe:/o:linux:linux_kernel")


def test_ipv6_only_hosts_are_parsed() -> None:
    assert any(host.ip == "2001:db8::1" for host in parse_nmap_xml(MULTI_HOST).hosts)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not xml at all",
        b"<nmaprun><host>",
        b"<?xml version='1.0'?><nmaprun><host><status state='up'/>",
    ],
)
def test_malformed_xml_raises_rather_than_returning_empty(payload: bytes) -> None:
    with pytest.raises(XmlParseError):
        parse_nmap_xml(payload)


def test_a_non_nmap_document_is_rejected() -> None:
    with pytest.raises(XmlParseError, match="nmaprun"):
        parse_nmap_xml(b"<html><body>proxy error</body></html>")


def test_hosts_without_an_address_are_skipped_not_crashed() -> None:
    payload = b"""<nmaprun version="7.99" start="1"><host><status state="up"/></host>
    <runstats><finished time="2"/></runstats></nmaprun>"""
    assert parse_nmap_xml(payload).hosts == ()


def test_unparseable_attributes_degrade_gracefully() -> None:
    payload = b"""<nmaprun version="7.99" start="not-a-number">
    <host><status state="up"/><address addr="10.0.4.12" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="oops"><state state="open"/></port>
    <port protocol="tcp" portid="22"><state state="open"/></port></ports></host>
    <runstats><finished time="also-bad"/></runstats></nmaprun>"""
    scan = parse_nmap_xml(payload)

    assert [port.port for port in scan.hosts[0].ports] == [22]
    assert scan.started_at is not None


def test_a_port_without_a_service_element_still_parses() -> None:
    payload = b"""<nmaprun version="7.99" start="1"><host><status state="up"/>
    <address addr="10.0.4.12" addrtype="ipv4"/>
    <ports><port protocol="udp" portid="53"><state state="open|filtered"/></port></ports></host>
    <runstats><finished time="2"/></runstats></nmaprun>"""
    port = parse_nmap_xml(payload).hosts[0].ports[0]

    assert (port.port, port.protocol, port.state) == (53, "udp", "open|filtered")
    assert port.service is None and port.cpes == ()
