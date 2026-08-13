"""Target validation against the agent's locally configured allowlist.

This is the security boundary that matters most in the agent (docs/AGENT-PROTOCOL.md §4).

Rules, in order:

1. The target is parsed with :mod:`ipaddress`. Never string comparison, never a prefix
   match on text. ``10.0.0.0/8`` and ``10.0.0.0/80`` and ``100.0.0.0/8`` are not
   distinguishable by string prefix; they are trivially distinguishable as networks.
2. The target must be *contained by* an entry in the LOCAL allowlist — the one read from
   the agent's own config file. If it is not, the job is rejected and nmap is never run.
3. The allowlist the server pushed via /heartbeat may only ever NARROW the local one.
   It is intersected with the local list; because CIDR ranges are either disjoint or
   nested, the intersection is exactly the more specific of each overlapping pair. A
   server range that is wider than, or disjoint from, the local list can therefore never
   grant new reach.

A compromised control plane cannot turn a customer's agent into a scanner-for-hire,
because the server never gets a vote on rule 2.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network

from .errors import InvalidNetworkError

Network = IPv4Network | IPv6Network

REASON_MALFORMED_TARGET = "malformed_target"
REASON_NOT_IN_LOCAL = "target_not_in_local_allowlist"
REASON_NOT_IN_NARROWED = "target_not_in_narrowed_allowlist"


@dataclass(frozen=True, slots=True)
class AllowlistDecision:
    """The outcome of validating one target. Immutable; carries its own justification."""

    allowed: bool
    target: str
    reason: str | None = None
    detail: str | None = None


def parse_network(value: str) -> Network:
    """Parse a single CIDR or bare address.

    strict=True on purpose: ``10.0.4.12/24`` is rejected rather than silently widened to
    ``10.0.4.0/24``. A target with host bits set is a malformed job, not a /24 scan.
    """
    if not isinstance(value, str) or not value.strip():
        raise InvalidNetworkError("empty or non-string network value")
    try:
        return ip_network(value.strip(), strict=True)
    except ValueError as exc:
        raise InvalidNetworkError(f"invalid network {value!r}: {exc}") from exc


def parse_networks(values: Iterable[str]) -> tuple[Network, ...]:
    """Parse an iterable of CIDR strings, failing on the first bad entry."""
    return tuple(parse_network(v) for v in values)


def _contained_by(target: Network, networks: Sequence[Network]) -> Network | None:
    """Return the first network that contains ``target``, or None.

    Address families are compared explicitly: ``subnet_of`` raises TypeError across
    versions, and an exception here would be a validation bypass if it were caught
    somewhere careless.
    """
    for candidate in networks:
        if candidate.version != target.version:
            continue
        if target.subnet_of(candidate):  # type: ignore[arg-type]
            return candidate
    return None


def narrow(local: Sequence[Network], server: Sequence[Network] | None) -> tuple[Network, ...]:
    """Intersect the local allowlist with the server-supplied one.

    ``server is None`` means the server did not express an opinion, so the local list
    stands unchanged. An explicitly empty server list narrows to nothing.

    Two CIDR ranges are either disjoint or one contains the other, so the intersection of
    an overlapping pair is simply the more specific of the two. Nothing outside ``local``
    can ever appear in the result.
    """
    if server is None:
        return tuple(local)

    effective: list[Network] = []
    for local_net in local:
        for server_net in server:
            if local_net.version != server_net.version:
                continue
            if local_net.subnet_of(server_net):  # type: ignore[arg-type]
                effective.append(local_net)
            elif server_net.subnet_of(local_net):  # type: ignore[arg-type]
                effective.append(server_net)
    return tuple(dict.fromkeys(effective))


def evaluate_target(
    target: str,
    local: Sequence[Network],
    server: Sequence[Network] | None = None,
) -> AllowlistDecision:
    """Decide whether ``target`` may be scanned. Pure function; no I/O, no logging."""
    try:
        parsed = parse_network(target)
    except InvalidNetworkError as exc:
        return AllowlistDecision(False, target, REASON_MALFORMED_TARGET, str(exc))

    if not local:
        return AllowlistDecision(
            False, target, REASON_NOT_IN_LOCAL, "agent has an empty local allowlist"
        )

    local_match = _contained_by(parsed, local)
    if local_match is None:
        return AllowlistDecision(
            False,
            target,
            REASON_NOT_IN_LOCAL,
            f"{parsed} not within configured ranges ({', '.join(str(n) for n in local)})",
        )

    effective = narrow(local, server)
    if _contained_by(parsed, effective) is None:
        return AllowlistDecision(
            False,
            target,
            REASON_NOT_IN_NARROWED,
            f"{parsed} excluded by the server-narrowed allowlist",
        )

    return AllowlistDecision(True, target, detail=f"{parsed} within {local_match}")
