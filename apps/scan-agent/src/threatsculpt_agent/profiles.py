"""Fixed nmap scan profiles.

A job supplies a profile *name*. It never supplies flags. This map is the only place
nmap arguments are defined, and the values are immutable tuples so a caller cannot
mutate the shared profile table.

Source of truth: docs/AGENT-PROTOCOL.md "Agent security requirements".
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from .errors import UnknownProfileError

SCAN_PROFILES: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "discovery": ("-sn", "-PE", "-PS443,80", "-T3"),
        "service": (
            "-sS",
            "-sV",
            "--version-intensity",
            "5",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
        ),
        "vulnerability": (
            "-sS",
            "-sV",
            "--version-intensity",
            "7",
            "-O",
            "-T3",
            "-p-",
        ),
    }
)

PROFILE_NAMES: tuple[str, ...] = tuple(SCAN_PROFILES)


def resolve_profile(name: str) -> tuple[str, ...]:
    """Return the argument vector for a profile name.

    Raises UnknownProfileError for anything not in the fixed map — including attempts
    to smuggle flags through the profile field.
    """
    try:
        return SCAN_PROFILES[name]
    except KeyError:
        raise UnknownProfileError(
            f"unknown scan profile {name!r}; known profiles: {', '.join(PROFILE_NAMES)}"
        ) from None
