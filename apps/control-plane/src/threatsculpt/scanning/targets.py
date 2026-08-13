"""Containment rules for scan targets and submitted hosts.

One module owns the question "is this address inside a network we are allowed to
touch?", because it is asked in three places that must agree:

* job creation — the target must sit inside a registered, **authorized** network;
* result ingest — every submitted host must sit inside the job's target *and*
  inside a registered network;
* heartbeat — the allowlist handed to an agent is narrowed to authorized ranges.

Answering it in Python rather than with PostgreSQL's ``<<=`` is deliberate: ingest
checks hundreds of hosts against a handful of networks, and a per-host round trip
to the database would be the slowest part of the endpoint. The values still come
out of native ``cidr``/``inet`` columns, so nothing here is parsing user text that
the database was trusted to validate.

Every function is pure and total: an unparseable value is *not contained*, never
an exception that a caller might forget to handle into an accidental allow.
"""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

IpNetwork = IPv4Network | IPv6Network
IpAddress = IPv4Address | IPv6Address


def parse_network(value: str) -> IpNetwork | None:
    """A CIDR, or ``None`` if the value is not one. Never raises."""
    try:
        return ip_network(value, strict=False)
    except ValueError:
        return None


def parse_address(value: str) -> IpAddress | None:
    """A host address, or ``None`` if the value is not one. Never raises."""
    try:
        return ip_address(value)
    except ValueError:
        return None


def network_contains_network(outer: str, inner: str) -> bool:
    """True when every address of ``inner`` is inside ``outer``.

    Mixed address families are simply not contained — ``subnet_of`` raises on a
    v4/v6 comparison, and a raised exception here would surface as a 500 on a
    request a client can craft.
    """
    outer_network = parse_network(outer)
    inner_network = parse_network(inner)
    if outer_network is None or inner_network is None:
        return False
    if outer_network.version != inner_network.version:
        return False
    return inner_network.subnet_of(outer_network)  # type: ignore[arg-type]


def network_contains_address(outer: str, address: str) -> bool:
    """True when ``address`` falls inside ``outer``."""
    outer_network = parse_network(outer)
    host = parse_address(address)
    if outer_network is None or host is None:
        return False
    if outer_network.version != host.version:
        return False
    return host in outer_network


def first_containing_network(candidates: Iterable[str], target: str) -> str | None:
    """The first candidate CIDR that fully contains ``target``, if any."""
    for candidate in candidates:
        if network_contains_network(candidate, target):
            return candidate
    return None


def any_contains_address(candidates: Iterable[str], address: str) -> bool:
    """True when ``address`` falls inside at least one candidate CIDR."""
    return any(network_contains_address(candidate, address) for candidate in candidates)


def narrow_to(allowed: Iterable[str], requested: Iterable[str]) -> tuple[str, ...]:
    """Keep only the requested ranges that are fully inside an allowed range.

    Used for the agent allowlist: a per-agent restriction may only ever narrow
    what the org has authorized, never widen it. An agent with no restriction of
    its own gets the allowed set unchanged.
    """
    allowed_list = list(allowed)
    requested_list = list(requested)
    if not requested_list:
        return tuple(allowed_list)
    return tuple(
        entry
        for entry in requested_list
        if first_containing_network(allowed_list, entry) is not None
    )
