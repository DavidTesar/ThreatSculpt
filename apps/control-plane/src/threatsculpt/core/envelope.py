"""The response envelope defined in docs/API.md.

    {"data": <payload>, "error": null, "meta": {...}}

``meta`` is present only on paginated collections.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ErrorBody(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    message: str
    field: str | None = None


class PageMeta(BaseModel):
    model_config = ConfigDict(frozen=True)

    page: int
    per_page: int
    total: int


class Envelope[PayloadT](BaseModel):
    """Success envelope. ``error`` is always ``None`` here by construction."""

    model_config = ConfigDict(frozen=True)

    data: PayloadT | None = None
    error: ErrorBody | None = None
    meta: PageMeta | None = None


def ok[PayloadT](data: PayloadT, *, meta: PageMeta | None = None) -> Envelope[PayloadT]:
    return Envelope[PayloadT](data=data, error=None, meta=meta)


def error_payload(code: str, message: str, field: str | None = None) -> dict[str, object]:
    """Plain dict form, for use inside a ``JSONResponse`` in exception handlers."""
    return {
        "data": None,
        "error": {"code": code, "message": message, "field": field},
    }
