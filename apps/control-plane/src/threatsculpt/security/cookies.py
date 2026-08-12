"""Refresh-token cookie handling.

``HttpOnly`` so script cannot read it, ``Secure`` so it never crosses plain
HTTP, ``SameSite=Lax`` so a third-party page cannot silently mint access tokens
with it, and ``Path`` narrowed to the auth routes so it is not attached to every
API call.
"""

from __future__ import annotations

from fastapi import Response

from threatsculpt.config import Settings

REFRESH_COOKIE_PATH_SUFFIX = "/auth"


def refresh_cookie_path(settings: Settings) -> str:
    return f"{settings.api_prefix}{REFRESH_COOKIE_PATH_SUFFIX}"


def set_refresh_cookie(
    response: Response, settings: Settings, token: str, *, max_age_seconds: int
) -> None:
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        max_age=max_age_seconds,
        path=refresh_cookie_path(settings),
        domain=settings.cookie_domain or None,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )


def clear_refresh_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        path=refresh_cookie_path(settings),
        domain=settings.cookie_domain or None,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
