"""Software version comparison and NVD version ranges.

Why not just compare strings: ``1.10`` sorts before ``1.9`` lexicographically,
so a naive comparison puts every 1.10.x host inside a "fixed in 1.9" range and
reports a vulnerability that was patched a year ago. False positives are the
fastest way to make a security product ignorable, so the comparison here is
segment-aware.

The rules, which are the ones dpkg and rpm converged on:

* A version splits into runs of digits and runs of non-digits.
* Digit runs compare numerically, so ``10 > 9`` and leading zeros do not matter.
* Non-digit runs compare lexicographically.
* A digit run outranks a non-digit run, so ``1.2.1 > 1.2.beta``.
* When one version runs out of segments, the longer one wins if its next
  segment is numeric and loses if it is alphabetic — which is what makes
  ``1.2 < 1.2.1`` and ``1.2 > 1.2-beta`` both true.

This is not a universal ordering for every vendor's scheme, and it does not try
to be. It is correct for dotted-numeric versions with pre-release suffixes,
which is what NVD ranges and nmap service banners actually contain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

_SEGMENT = re.compile(r"(\d+|[A-Za-z]+)")

#: Versions carrying no comparable segment at all (``*``, ``-``, empty).
UNKNOWN_VERSIONS: Final = frozenset({"", "*", "-", "unknown"})

_NUMERIC_RANK: Final = 1
_ALPHA_RANK: Final = 0


def is_known_version(value: str | None) -> bool:
    """False for the CPE placeholders that mean "any" or "not applicable"."""
    if not value:
        return False
    return value.strip().lower() not in UNKNOWN_VERSIONS


def _segments(value: str) -> tuple[tuple[int, int | str], ...]:
    """Split into ranked segments. Rank orders numeric above alphabetic."""
    parts: list[tuple[int, int | str]] = []
    for token in _SEGMENT.findall(value):
        if token.isdigit():
            parts.append((_NUMERIC_RANK, int(token)))
        else:
            parts.append((_ALPHA_RANK, token.lower()))
    return tuple(parts)


def compare_versions(left: str, right: str) -> int:
    """``-1`` / ``0`` / ``1`` for left < right, equal, left > right."""
    left_parts = _segments(left)
    right_parts = _segments(right)

    for left_part, right_part in zip(left_parts, right_parts, strict=False):
        verdict = _compare_segment(left_part, right_part)
        if verdict != 0:
            return verdict

    return _compare_tail(left_parts, right_parts)


def _compare_segment(left: tuple[int, int | str], right: tuple[int, int | str]) -> int:
    left_rank, left_value = left
    right_rank, right_value = right
    if left_rank != right_rank:
        # Numeric outranks alphabetic: 1.2.1 > 1.2.beta.
        return 1 if left_rank > right_rank else -1
    if left_value == right_value:
        return 0
    return 1 if left_value > right_value else -1  # type: ignore[operator]


def _compare_tail(
    left: tuple[tuple[int, int | str], ...], right: tuple[tuple[int, int | str], ...]
) -> int:
    """Break the tie when one version has segments the other does not."""
    if len(left) == len(right):
        return 0
    longer, sign = (left, 1) if len(left) > len(right) else (right, -1)
    next_rank, _ = longer[min(len(left), len(right))]
    # A trailing numeric segment is an increment (1.2.1 > 1.2); a trailing
    # alphabetic segment is a pre-release marker (1.2-beta < 1.2).
    return sign if next_rank == _NUMERIC_RANK else -sign


@dataclass(frozen=True, slots=True)
class VersionRange:
    """An NVD affected-version window. All bounds optional.

    An instance with no bounds at all means "every version", which is a real
    NVD state and is deliberately distinguishable from "we do not know".
    """

    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None

    @property
    def is_bounded(self) -> bool:
        return any(
            (self.start_including, self.start_excluding, self.end_including, self.end_excluding)
        )

    def contains(self, version: str) -> bool:
        """Whether ``version`` falls inside the window.

        An unbounded range contains everything. An unknown version is contained
        by nothing except an unbounded range — refusing to guess is the point.
        """
        if not self.is_bounded:
            return True
        if not is_known_version(version):
            return False
        return self._above_lower_bound(version) and self._below_upper_bound(version)

    def _above_lower_bound(self, version: str) -> bool:
        if self.start_including is not None and compare_versions(version, self.start_including) < 0:
            return False
        return not (
            self.start_excluding is not None
            and compare_versions(version, self.start_excluding) <= 0
        )

    def _below_upper_bound(self, version: str) -> bool:
        if self.end_including is not None and compare_versions(version, self.end_including) > 0:
            return False
        return not (
            self.end_excluding is not None and compare_versions(version, self.end_excluding) >= 0
        )

    def describe(self) -> str:
        """Human-readable window, for the match explanation."""
        if not self.is_bounded:
            return "all versions"
        lower = (
            f">= {self.start_including}"
            if self.start_including
            else (f"> {self.start_excluding}" if self.start_excluding else None)
        )
        upper = (
            f"<= {self.end_including}"
            if self.end_including
            else (f"< {self.end_excluding}" if self.end_excluding else None)
        )
        return " and ".join(part for part in (lower, upper) if part)
