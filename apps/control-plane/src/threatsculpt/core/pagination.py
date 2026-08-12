"""Pagination primitives.

docs/API.md: all collections paginate, default 50, max 200, and no unbounded
query reaches the database. ``PaginationParams`` is the only thing the
repository layer accepts for limiting, so "forgot the LIMIT" is not reachable.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, TypeVar

from fastapi import Query

from threatsculpt.core.envelope import PageMeta

DEFAULT_PER_PAGE = 50
MAX_PER_PAGE = 200

ItemT = TypeVar("ItemT")


@dataclass(frozen=True, slots=True)
class PaginationParams:
    page: int = 1
    per_page: int = DEFAULT_PER_PAGE

    def __post_init__(self) -> None:
        if self.page < 1:
            raise ValueError("page must be >= 1")
        if not 1 <= self.per_page <= MAX_PER_PAGE:
            raise ValueError(f"per_page must be between 1 and {MAX_PER_PAGE}")

    @property
    def limit(self) -> int:
        return self.per_page

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.per_page

    def meta(self, total: int) -> PageMeta:
        return PageMeta(page=self.page, per_page=self.per_page, total=total)


def pagination_params(
    page: Annotated[int, Query(ge=1, description="1-based page number")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=MAX_PER_PAGE, description="Items per page (max 200)")
    ] = DEFAULT_PER_PAGE,
) -> PaginationParams:
    """FastAPI dependency. Bounds are enforced by the query validators above."""
    return PaginationParams(page=page, per_page=per_page)


@dataclass(frozen=True, slots=True)
class Page[ItemT]:
    """A slice of a collection plus the total count for the same predicate."""

    items: tuple[ItemT, ...]
    total: int
    params: PaginationParams

    def map[OutT](self, transform: Callable[[ItemT], OutT]) -> Page[OutT]:
        """Return a new Page with each item transformed. Never mutates self."""
        return Page(
            items=tuple(transform(item) for item in self.items),
            total=self.total,
            params=self.params,
        )

    @property
    def meta(self) -> PageMeta:
        return self.params.meta(self.total)
