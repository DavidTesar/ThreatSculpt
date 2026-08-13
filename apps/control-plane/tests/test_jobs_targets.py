"""Unit tests for the containment rules in ``scanning.targets``.

Pure functions, no database. These cover the cases the HTTP suites cannot reach
cheaply — mixed address families, garbage input, boundary addresses — and they
pin the property that matters most: **a value these functions cannot parse is not
contained.** An exception here would surface as a 500 on a request any client can
craft, and a permissive default would let a malformed address through the ingest
check entirely.
"""

from __future__ import annotations

import pytest

from threatsculpt.scanning.targets import (
    any_contains_address,
    first_containing_network,
    narrow_to,
    network_contains_address,
    network_contains_network,
    parse_address,
    parse_network,
)


@pytest.mark.parametrize(
    ("outer", "inner", "expected"),
    [
        ("10.0.0.0/8", "10.0.4.0/24", True),
        ("10.0.0.0/8", "10.0.0.0/8", True),
        ("10.0.4.0/24", "10.0.0.0/8", False),
        ("10.0.0.0/8", "11.0.0.0/8", False),
        ("192.168.0.0/16", "192.168.1.0/24", True),
        ("2001:db8::/32", "2001:db8:1::/48", True),
        ("2001:db8:1::/48", "2001:db8::/32", False),
    ],
)
def test_network_containment(outer: str, inner: str, expected: bool) -> None:
    assert network_contains_network(outer, inner) is expected


def test_mixed_address_families_are_not_contained() -> None:
    """``subnet_of`` raises across families; a raised exception here would be a
    500 on a request a client controls."""
    assert network_contains_network("10.0.0.0/8", "2001:db8::/32") is False
    assert network_contains_network("2001:db8::/32", "10.0.0.0/8") is False
    assert network_contains_address("2001:db8::/32", "10.0.4.12") is False


@pytest.mark.parametrize(
    ("outer", "address", "expected"),
    [
        ("10.0.4.0/24", "10.0.4.12", True),
        ("10.0.4.0/24", "10.0.4.0", True),
        ("10.0.4.0/24", "10.0.4.255", True),
        ("10.0.4.0/24", "10.0.5.1", False),
        ("10.0.4.0/24", "10.0.3.255", False),
        ("0.0.0.0/0", "8.8.8.8", True),
        ("2001:db8::/32", "2001:db8::1", True),
    ],
)
def test_address_containment(outer: str, address: str, expected: bool) -> None:
    assert network_contains_address(outer, address) is expected


@pytest.mark.parametrize(
    "garbage",
    ["", "not-a-cidr", "10.0.4.0/99", "10.0.4.999/24", "'; DROP TABLE networks; --", "10.0.4"],
)
def test_unparseable_values_are_never_contained(garbage: str) -> None:
    assert parse_network(garbage) is None or parse_address(garbage) is None
    assert network_contains_network("10.0.0.0/8", garbage) is False
    assert network_contains_network(garbage, "10.0.4.0/24") is False
    assert network_contains_address("10.0.0.0/8", garbage) is False
    assert network_contains_address(garbage, "10.0.4.12") is False


def test_a_host_address_with_a_prefix_normalises_to_its_network() -> None:
    """``10.0.4.12/24`` is what a ``cidr`` column stores as ``10.0.4.0/24``."""
    network = parse_network("10.0.4.12/24")
    assert network is not None
    assert str(network) == "10.0.4.0/24"


def test_first_containing_network_returns_the_first_match() -> None:
    candidates = ("192.168.0.0/16", "10.0.0.0/8", "10.0.0.0/16")
    assert first_containing_network(candidates, "10.0.4.0/24") == "10.0.0.0/8"
    assert first_containing_network(candidates, "8.8.8.0/24") is None
    assert first_containing_network((), "10.0.4.0/24") is None


def test_any_contains_address() -> None:
    candidates = ("192.168.0.0/16", "10.0.0.0/8")
    assert any_contains_address(candidates, "10.0.4.12") is True
    assert any_contains_address(candidates, "8.8.8.8") is False
    assert any_contains_address((), "10.0.4.12") is False


def test_narrowing_keeps_only_ranges_inside_the_allowed_set() -> None:
    allowed = ("10.0.0.0/8",)
    assert narrow_to(allowed, ("10.0.4.0/24", "192.168.0.0/16")) == ("10.0.4.0/24",)


def test_narrowing_with_no_request_returns_the_allowed_set_unchanged() -> None:
    """An agent with no restriction of its own gets everything the org allows."""
    allowed = ("10.0.0.0/8", "192.168.0.0/16")
    assert narrow_to(allowed, ()) == allowed


def test_narrowing_can_never_widen() -> None:
    """The property, stated directly: nothing survives that the org did not allow."""
    allowed = ("10.0.4.0/24",)
    requested = ("10.0.0.0/8", "0.0.0.0/0", "10.0.4.0/25")
    result = narrow_to(allowed, requested)
    assert result == ("10.0.4.0/25",)
    assert all(network_contains_network("10.0.4.0/24", entry) for entry in result)


def test_narrowing_an_empty_allowed_set_yields_nothing() -> None:
    assert narrow_to((), ("10.0.0.0/8",)) == ()
    assert narrow_to((), ()) == ()
