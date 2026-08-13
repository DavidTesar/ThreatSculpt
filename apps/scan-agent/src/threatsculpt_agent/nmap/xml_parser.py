"""Parse nmap's XML output.

v1 parsed ``python-nmap``'s stringified dicts and split them on tabs, which broke on any
format change and silently produced garbage. This module reads nmap's own machine-readable
XML (``-oX -``), which carries a declared ``xmloutputversion`` and is stable across
releases, using the stdlib ``xml.etree.ElementTree``.

Only observations are extracted — host, ports, service, product, version, CPE, OS. No CVE
and no severity: enrichment is the control plane's job (docs/ARCHITECTURE.md).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from xml.etree import ElementTree as ET

from ..errors import XmlParseError
from ..models import HostObservation, OsObservation, ParsedScan, PortObservation

log = logging.getLogger(__name__)

DEFAULT_PORT_STATES: tuple[str, ...] = ("open", "open|filtered")
UP = "up"


def parse_nmap_xml(
    data: bytes | str,
    *,
    include_port_states: Sequence[str] | None = DEFAULT_PORT_STATES,
    include_down_hosts: bool = False,
) -> ParsedScan:
    """Turn nmap XML into a ParsedScan.

    ``include_port_states=None`` keeps every port nmap reported. The default keeps only
    open and open|filtered: a top-1000 scan reports ~1000 closed ports per host, and
    submitting those would blow the payload cap without adding an observation anyone acts
    on.
    """
    root = _parse_root(data)
    if root.tag != "nmaprun":
        raise XmlParseError(f"expected an <nmaprun> document, got <{root.tag}>")

    started = _epoch_attr(root, "start")
    finished_el = root.find("./runstats/finished")
    finished = _epoch_attr(finished_el, "time") if finished_el is not None else started

    hosts = tuple(
        host
        for host in (_parse_host(el, include_port_states) for el in root.findall("host"))
        if host is not None and (include_down_hosts or host.state == UP)
    )

    return ParsedScan(
        nmap_version=root.get("version", "unknown"),
        started_at=started,
        finished_at=finished,
        hosts=hosts,
        hosts_up=sum(1 for host in hosts if host.state == UP),
        hosts_total=len(root.findall("host")),
    )


def _parse_root(data: bytes | str) -> ET.Element:
    try:
        return ET.fromstring(data)  # noqa: S314 - stdlib ET does not resolve external entities
    except ET.ParseError as exc:
        raise XmlParseError(f"nmap produced malformed XML: {exc}") from exc


def _epoch_attr(element: ET.Element | None, name: str) -> datetime:
    raw = element.get(name) if element is not None else None
    if not raw:
        return datetime.now(tz=UTC)
    try:
        return datetime.fromtimestamp(int(raw), tz=UTC)
    except (ValueError, OSError, OverflowError):
        log.warning("unparseable nmap timestamp %r for attribute %s", raw, name)
        return datetime.now(tz=UTC)


def _parse_host(
    element: ET.Element, include_port_states: Sequence[str] | None
) -> HostObservation | None:
    ip = _primary_address(element)
    if ip is None:
        log.warning("skipping <host> with no IPv4/IPv6 address")
        return None

    status = element.find("status")
    state = status.get("state", "unknown") if status is not None else "unknown"

    return HostObservation(
        ip=ip,
        hostname=_hostname(element),
        mac=_address_of_type(element, "mac"),
        state=state,
        os=_parse_os(element),
        ports=_parse_ports(element, include_port_states),
    )


def _primary_address(element: ET.Element) -> str | None:
    return _address_of_type(element, "ipv4") or _address_of_type(element, "ipv6")


def _address_of_type(element: ET.Element, addrtype: str) -> str | None:
    for address in element.findall("address"):
        if address.get("addrtype") == addrtype:
            value = address.get("addr")
            if value:
                return value
    return None


def _hostname(element: ET.Element) -> str | None:
    """Prefer the PTR name; fall back to whatever nmap listed first."""
    names = element.findall("./hostnames/hostname")
    for hostname in names:
        if hostname.get("type") == "PTR" and hostname.get("name"):
            return hostname.get("name")
    for hostname in names:
        if hostname.get("name"):
            return hostname.get("name")
    return None


def _parse_os(element: ET.Element) -> OsObservation | None:
    """Take the highest-accuracy osmatch, and the OS family/generation under it."""
    matches = element.findall("./os/osmatch")
    if not matches:
        return None
    best = max(matches, key=lambda match: _int_or_zero(match.get("accuracy")))
    osclass = best.find("osclass")
    family = osclass.get("osfamily") if osclass is not None else None
    version = osclass.get("osgen") if osclass is not None else None
    accuracy = _int_or_none(best.get("accuracy"))
    if family is None and version is None and accuracy is None:
        return None
    return OsObservation(family=family, version=version, accuracy=accuracy)


def _parse_ports(
    element: ET.Element, include_port_states: Sequence[str] | None
) -> tuple[PortObservation, ...]:
    allowed = set(include_port_states) if include_port_states is not None else None
    ports: list[PortObservation] = []
    for port in element.findall("./ports/port"):
        parsed = _parse_port(port)
        if parsed is None:
            continue
        if allowed is None or parsed.state in allowed:
            ports.append(parsed)
    return tuple(ports)


def _parse_port(element: ET.Element) -> PortObservation | None:
    portid = _int_or_none(element.get("portid"))
    if portid is None or not 0 <= portid <= 65535:
        log.warning("skipping <port> with unusable portid %r", element.get("portid"))
        return None

    state_el = element.find("state")
    service_el = element.find("service")
    return PortObservation(
        port=portid,
        protocol=element.get("protocol", "tcp"),
        state=state_el.get("state", "unknown") if state_el is not None else "unknown",
        service=service_el.get("name") if service_el is not None else None,
        product=service_el.get("product") if service_el is not None else None,
        version=service_el.get("version") if service_el is not None else None,
        cpes=_cpes(service_el),
    )


def _cpes(service_el: ET.Element | None) -> tuple[str, ...]:
    if service_el is None:
        return ()
    return tuple(
        cpe.text.strip() for cpe in service_el.findall("cpe") if cpe.text and cpe.text.strip()
    )


def _int_or_none(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _int_or_zero(raw: str | None) -> int:
    return _int_or_none(raw) or 0


def total_ports(hosts: Iterable[HostObservation]) -> int:
    """Convenience for logging/metrics."""
    return sum(len(host.ports) for host in hosts)
