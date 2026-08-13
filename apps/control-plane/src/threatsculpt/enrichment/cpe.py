"""CPE 2.3 parsing and component comparison.

Both bindings are accepted, because both turn up in practice: NVD publishes
CPE 2.3 formatted strings (``cpe:2.3:a:apache:http_server:2.4.49:*:...``) while
nmap still emits the 2.2 URI binding (``cpe:/a:apache:http_server:2.4.49``). A
matcher that understands only one of them silently matches nothing for half its
inputs, which looks exactly like "no vulnerabilities found".

Comparison is per-component and exact — never substring. ``substring in
other_product`` is the single decision that turns a vulnerability scanner into a
noise generator: it maps ``http_server`` onto ``http_server_proxy``, and
``tomcat`` onto ``tomcat_native``, and every one of those is a false positive an
operator has to disprove by hand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

#: CPE's two special component values.
ANY: Final = "*"
NA: Final = "-"

_CPE23_PREFIX: Final = "cpe:2.3:"
_CPE22_PREFIX: Final = "cpe:/"

#: 2.3 has 11 components; 2.2's URI binding carries only the first 7.
_CPE23_COMPONENTS: Final = 11
_CPE22_COMPONENTS: Final = 7

_UNESCAPE = re.compile(r"\\(.)")


class Relation(StrEnum):
    """How an observed component relates to a CVE's criteria component."""

    #: Same concrete value.
    EQUAL = "equal"
    #: The criteria says ANY, so it covers whatever was observed.
    SUPERSET = "superset"
    #: We observed ANY (i.e. we do not know) where the criteria is specific.
    UNDETERMINED = "undetermined"
    #: Concrete values that differ.
    DISJOINT = "disjoint"


@dataclass(frozen=True, slots=True)
class Cpe:
    """A parsed CPE name. Components are unescaped and lower-cased."""

    part: str = ANY
    vendor: str = ANY
    product: str = ANY
    version: str = ANY
    update: str = ANY
    edition: str = ANY
    language: str = ANY
    sw_edition: str = ANY
    target_sw: str = ANY
    target_hw: str = ANY
    other: str = ANY

    @property
    def is_specific_enough_to_match(self) -> bool:
        """A criteria naming neither vendor nor product matches the whole world.

        NVD does not publish such entries, but a malformed mirror row could, and
        acting on one would attach every CVE to every host.
        """
        return self.vendor != ANY and self.product != ANY

    def identity(self) -> str:
        """``vendor:product`` — the part of a CPE that names the software."""
        return f"{self.vendor}:{self.product}"

    def to_cpe23(self) -> str:
        return _CPE23_PREFIX + ":".join(
            (
                self.part,
                self.vendor,
                self.product,
                self.version,
                self.update,
                self.edition,
                self.language,
                self.sw_edition,
                self.target_sw,
                self.target_hw,
                self.other,
            )
        )


def parse_cpe(value: str) -> Cpe | None:
    """Parse either CPE binding. ``None`` when the input is not a CPE."""
    if not value:
        return None
    candidate = value.strip()
    lowered = candidate.lower()
    if lowered.startswith(_CPE23_PREFIX):
        return _from_components(_split_escaped(candidate[len(_CPE23_PREFIX) :]), _CPE23_COMPONENTS)
    if lowered.startswith(_CPE22_PREFIX):
        return _from_components(_split_escaped(candidate[len(_CPE22_PREFIX) :]), _CPE22_COMPONENTS)
    return None


def _split_escaped(body: str) -> list[str]:
    """Split on ``:`` while honouring backslash escapes.

    ``str.split`` would cut ``cpe:2.3:a:vendor:some\\:product:1.0`` in the wrong
    place and shift every later component by one, silently producing a CPE for
    different software.
    """
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in body:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _from_components(parts: list[str], expected: int) -> Cpe | None:
    if len(parts) < 2:
        return None
    padded = [*parts[:expected], *([ANY] * (expected - len(parts)))]
    normalised = [_normalise_component(part) for part in padded]
    if expected == _CPE22_COMPONENTS:
        # 2.2 has no sw_edition/target_sw/target_hw/other; they are unknown, not absent.
        normalised.extend([ANY] * (_CPE23_COMPONENTS - _CPE22_COMPONENTS))
    return Cpe(*normalised[:_CPE23_COMPONENTS])


def _normalise_component(value: str) -> str:
    """Unescape, lower-case, and map the empty string to ANY.

    An empty component in a 2.2 URI (``cpe:/a:apache::2.4``) means "unspecified",
    which is the same statement ANY makes.
    """
    if value in (ANY, NA):
        return value
    unescaped = _UNESCAPE.sub(r"\1", value).strip().lower()
    return unescaped or ANY


def compare_component(observed: str, criteria: str) -> Relation:
    """Relate one observed component to the CVE's criteria for it."""
    if criteria == ANY:
        return Relation.SUPERSET
    if observed == ANY:
        return Relation.UNDETERMINED
    if observed == criteria:
        return Relation.EQUAL
    return Relation.DISJOINT


#: Components compared for software identity. ``version`` is handled separately
#: because it needs range logic rather than equality, and ``language`` /
#: ``edition`` are skipped: NVD populates them inconsistently, and treating a
#: mismatch there as disjoint drops true positives.
IDENTITY_COMPONENTS: Final = ("part", "vendor", "product")

#: Compared when both sides state a concrete value. A disagreement here is real
#: (``target_sw=windows`` against a Linux host), but an unknown is not evidence.
QUALIFIER_COMPONENTS: Final = ("update", "sw_edition", "target_sw", "target_hw")


def identity_matches(observed: Cpe, criteria: Cpe) -> bool:
    """Whether the two names describe the same software, ignoring version."""
    for component in IDENTITY_COMPONENTS:
        relation = compare_component(getattr(observed, component), getattr(criteria, component))
        if relation in (Relation.DISJOINT, Relation.UNDETERMINED):
            return False
    return True


def qualifiers_conflict(observed: Cpe, criteria: Cpe) -> bool:
    """True when both sides name a qualifier concretely and they disagree."""
    return any(
        compare_component(getattr(observed, component), getattr(criteria, component))
        is Relation.DISJOINT
        for component in QUALIFIER_COMPONENTS
    )


def normalise_product_name(value: str) -> str:
    """Fold a human product string toward CPE's product component.

    ``"Apache httpd"`` and ``"apache_httpd"`` become the same token. Used only
    by the low-confidence fallback path, and only for whole-token equality —
    never as a substring test.
    """
    collapsed = re.sub(r"[^a-z0-9]+", "_", value.strip().lower())
    return collapsed.strip("_")
