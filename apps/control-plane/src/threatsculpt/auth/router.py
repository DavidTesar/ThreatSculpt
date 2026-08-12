"""Auth endpoints. HTTP shape only — decisions live in ``auth.service``."""

from __future__ import annotations

from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from threatsculpt.api.dependencies import CurrentUser, SessionDep, SettingsDep, get_jwt_codec
from threatsculpt.api.limits import enforce_auth_rate_limit
from threatsculpt.api.middleware import client_ip
from threatsculpt.auth import service
from threatsculpt.auth.schemas import (
    LoginRequest,
    LogoutResponse,
    MeResponse,
    OrgSummary,
    RegisterRequest,
    RegisterResponse,
    TokenResponse,
    UserSummary,
)
from threatsculpt.auth.service import AuthOutcome, RequestFacts
from threatsculpt.config import Settings
from threatsculpt.core.envelope import Envelope, ok
from threatsculpt.models.org import Org
from threatsculpt.models.user import User
from threatsculpt.security.cookies import clear_refresh_cookie, set_refresh_cookie
from threatsculpt.security.tokens import JwtCodec

SECONDS_PER_DAY = 86_400

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    dependencies=[Depends(enforce_auth_rate_limit)],
)

CodecDep = Annotated[JwtCodec, Depends(get_jwt_codec)]


def _facts(request: Request) -> RequestFacts:
    return RequestFacts(
        user_agent=request.headers.get("user-agent"),
        ip=client_ip(request),
    )


def _user_summary(user: User) -> UserSummary:
    return UserSummary(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        status=user.status,
        last_login_at=user.last_login_at,
    )


def _org_summary(org: Org) -> OrgSummary:
    return OrgSummary(id=org.id, name=org.name, slug=org.slug, plan=org.plan, status=org.status)


def _attach_refresh_cookie(response: Response, settings: Settings, outcome: AuthOutcome) -> None:
    set_refresh_cookie(
        response,
        settings,
        outcome.refresh_token,
        max_age_seconds=settings.refresh_token_ttl_days * SECONDS_PER_DAY,
    )


@router.post(
    "/register",
    status_code=HTTPStatus.CREATED,
    response_model=Envelope[RegisterResponse],
    summary="Create an organisation and its owner user",
)
async def register(
    request: Request,
    response: Response,
    payload: RegisterRequest,
    session: SessionDep,
    settings: SettingsDep,
    codec: CodecDep,
) -> Envelope[RegisterResponse]:
    outcome = await service.register(session, settings, codec, payload, _facts(request))
    _attach_refresh_cookie(response, settings, outcome)
    return ok(
        RegisterResponse(
            user=_user_summary(outcome.user),
            org=_org_summary(outcome.org),
            access_token=outcome.access_token,
            expires_at=outcome.access_expires_at,
        )
    )


@router.post(
    "/login",
    response_model=Envelope[TokenResponse],
    summary="Exchange a password for an access token and a refresh cookie",
)
async def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    session: SessionDep,
    settings: SettingsDep,
    codec: CodecDep,
) -> Envelope[TokenResponse]:
    outcome = await service.login(
        session, request.app.state.session_factory, settings, codec, payload, _facts(request)
    )
    _attach_refresh_cookie(response, settings, outcome)
    return ok(
        TokenResponse(access_token=outcome.access_token, expires_at=outcome.access_expires_at)
    )


@router.post(
    "/refresh",
    response_model=Envelope[TokenResponse],
    summary="Rotate the refresh token and mint a new access token",
)
async def refresh(
    request: Request,
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
    codec: CodecDep,
) -> Envelope[TokenResponse]:
    """The refresh token comes from the cookie only — never from the body.

    Accepting it in a body would make it readable by script on any page that
    could be tricked into echoing it, which is the whole reason it is HttpOnly.
    """
    presented = request.cookies.get(settings.refresh_cookie_name, "")
    outcome = await service.rotate_refresh(
        session, settings, codec, presented, None, _facts(request)
    )
    _attach_refresh_cookie(response, settings, outcome)
    return ok(
        TokenResponse(access_token=outcome.access_token, expires_at=outcome.access_expires_at)
    )


@router.post(
    "/logout",
    response_model=Envelope[LogoutResponse],
    summary="Revoke the refresh token family",
)
async def logout(
    request: Request,
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
) -> Envelope[LogoutResponse]:
    """Always succeeds. Logging out is not an operation worth an error path."""
    presented = request.cookies.get(settings.refresh_cookie_name)
    revoked = await service.logout(session, presented, None, _facts(request))
    clear_refresh_cookie(response, settings)
    return ok(LogoutResponse(revoked=revoked))


@router.get(
    "/me",
    response_model=Envelope[MeResponse],
    summary="The authenticated user, their org, and their role",
)
async def me(principal: CurrentUser, session: SessionDep) -> Envelope[MeResponse]:
    org = await session.get(Org, principal.scope.org_id)
    assert org is not None  # the principal could not have authenticated otherwise
    return ok(MeResponse(user=_user_summary(principal.user), org=_org_summary(org)))
