"""What it takes to assert that a range may be scanned.

docs/ARCHITECTURE.md: *public-internet ranges are rejected unless the org has an
uploaded authorization record.* docs/SECURITY.md: *the ``authorized`` flag on a
network is not a formality — it is the record that you asserted you had
permission.* Neither was implemented. ``POST /networks`` took a boolean, and a
boolean anybody can set is not a record of anything: ``0.0.0.0/0`` with
``authorized: true`` was accepted, and a scan of ``1.1.1.1`` under it was
accepted too.

The distinction this module draws is between a range the org can only be
scanning itself and a range where being wrong means scanning somebody else:

* **Private / reserved** (RFC1918, CGNAT, link-local, loopback, IPv6 ULA…) keeps
  today's behaviour exactly. Pointing a scanner at your own ``10.0.0.0/8`` is the
  ordinary case this product exists for, and adding friction to it protects
  nobody.
* **Globally routable** requires a written assertion — a non-empty
  ``authorization_note`` — recorded together with the user who made it and when.
  That is the "record" the docs describe, in the only form this service has: it
  is attributable, timestamped, and it lands in the append-only audit log, so
  after the fact there is an answer to *who said we were allowed to scan this*.
* **Mixed** — a block that spans both, of which ``0.0.0.0/0`` is the extreme
  case — is refused outright with no note that could rescue it. A CIDR covering
  both a customer's own LAN and the whole internet is never a real ownership
  assertion, it is a range somebody typed to make the check go away.

The note is not verified, and this module does not pretend otherwise. It cannot
be: nothing here can tell a genuine engagement letter from a sentence somebody
typed. What it changes is that asserting permission over public address space is
now a deliberate, attributable act instead of a default-valued boolean, which is
the difference between a control and a formality.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_network

from threatsculpt.core.errors import SemanticValidationError

#: Blocks that are not the public internet. Registering one of these is an
#: ordinary act; every other range is somebody else's until proven otherwise.
#: Written out rather than using ``IPv4Network.is_private`` because that property
#: answers a question about a *whole* network and gives no way to tell "entirely
#: private" from "overlaps private", which is the distinction that matters here.
RESERVED_BLOCKS: tuple[IPv4Network | IPv6Network, ...] = (
    ip_network("0.0.0.0/8"),  # "this network"
    ip_network("10.0.0.0/8"),  # RFC1918
    ip_network("100.64.0.0/10"),  # RFC6598 carrier-grade NAT
    ip_network("127.0.0.0/8"),  # loopback
    ip_network("169.254.0.0/16"),  # link-local
    ip_network("172.16.0.0/12"),  # RFC1918
    ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ip_network("192.0.2.0/24"),  # TEST-NET-1
    ip_network("192.168.0.0/16"),  # RFC1918
    ip_network("198.18.0.0/15"),  # benchmarking
    ip_network("198.51.100.0/24"),  # TEST-NET-2
    ip_network("203.0.113.0/24"),  # TEST-NET-3
    ip_network("240.0.0.0/4"),  # reserved, includes broadcast
    ip_network("::1/128"),  # loopback
    ip_network("fc00::/7"),  # unique local
    ip_network("fe80::/10"),  # link-local
    ip_network("2001:db8::/32"),  # documentation
)

#: The largest public block one authorization record may cover. A /16 is 65,536
#: addresses — more than any enterprise this product targets owns publicly, and
#: an org that genuinely holds more registers it as several records, each with
#: its own assertion. The point is that one careless entry cannot authorise a
#: scan of a meaningful slice of the internet.
MIN_PUBLIC_PREFIX_LENGTH: dict[int, int] = {4: 16, 6: 32}


class NetworkClass(StrEnum):
    """What kind of address space a registered CIDR covers."""

    PRIVATE = "private"
    PUBLIC = "public"
    MIXED = "mixed"


@dataclass(frozen=True, slots=True)
class AuthorizationAssertion:
    """A validated request to mark a network authorized, and what it asserted."""

    network_class: NetworkClass
    #: True when the org had to put its assertion in writing for this range.
    requires_written_assertion: bool


def classify(cidr: str) -> NetworkClass:
    """Whether ``cidr`` is entirely reserved, entirely public, or spans both.

    Total: an unparseable value is ``MIXED``, the class that is always refused.
    Callers reach this only after schema validation has already parsed the value,
    so the fallback is a guard against a future caller, not a live path.
    """
    try:
        network = ip_network(cidr, strict=False)
    except ValueError:
        return NetworkClass.MIXED

    same_family = [block for block in RESERVED_BLOCKS if block.version == network.version]
    if any(_is_subnet(network, block) for block in same_family):
        return NetworkClass.PRIVATE
    if any(network.overlaps(block) for block in same_family):
        return NetworkClass.MIXED
    return NetworkClass.PUBLIC


def _is_subnet(network: IPv4Network | IPv6Network, block: IPv4Network | IPv6Network) -> bool:
    """``network`` lies entirely inside ``block``. Same family, checked by caller."""
    return network.subnet_of(block)  # type: ignore[arg-type]


def validate_authorization(
    cidr: str, *, authorized: bool, authorization_note: str | None
) -> AuthorizationAssertion:
    """Decide whether this registration may claim scan authorisation.

    Raises ``SemanticValidationError`` — 422, with the offending field named —
    rather than returning a flag, so a caller cannot proceed past a refusal by
    ignoring a falsy value.

    A network that is **not** marked authorized is only checked for absurdity.
    Recording ``0.0.0.0/0`` as an unauthorised inventory entry is still nonsense,
    but recording a public ``/24`` you have not yet got permission for is a
    perfectly reasonable thing to have in an inventory, so it is allowed without
    a note until somebody actually flips the flag.
    """
    network_class = classify(cidr)

    if network_class is NetworkClass.MIXED:
        raise SemanticValidationError(
            f"{cidr} spans both private and public address space and cannot be registered "
            "as a network you own. Register the ranges you actually hold, separately.",
            field="cidr",
            code="network_range_not_ownable",
        )

    if network_class is NetworkClass.PRIVATE or not authorized:
        return AuthorizationAssertion(network_class=network_class, requires_written_assertion=False)

    _reject_oversized_public_range(cidr)

    if not (authorization_note or "").strip():
        raise SemanticValidationError(
            f"{cidr} is public internet address space. Marking it authorized requires an "
            "authorization_note recording who permitted the scan and under what agreement; "
            "the note, the user who made the assertion and the time are all retained.",
            field="authorization_note",
            code="authorization_record_required",
        )

    return AuthorizationAssertion(network_class=network_class, requires_written_assertion=True)


def _reject_oversized_public_range(cidr: str) -> None:
    """Refuse a public block too large to be a credible ownership claim."""
    network = ip_network(cidr, strict=False)
    floor = MIN_PUBLIC_PREFIX_LENGTH[network.version]
    if network.prefixlen < floor:
        raise SemanticValidationError(
            f"{cidr} covers more public address space than one authorization record may "
            f"claim (the limit is a /{floor}). Register the ranges you hold individually.",
            field="cidr",
            code="public_range_too_large",
        )
