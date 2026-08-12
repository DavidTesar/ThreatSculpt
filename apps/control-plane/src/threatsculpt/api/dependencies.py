"""FastAPI dependency chains.

Two authentication chains that share no code path:

    current_user   Authorization: Bearer <JWT>       -> UserPrincipal
    current_agent  Authorization: Bearer tsa_<key>   -> AgentPrincipal

An agent key presented to a dashboard route fails JWT signature verification. A
user JWT presented to an agent route hashes to nothing in ``agents``. Neither
outcome depends on remembering to check a flag.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.auth.principals import AgentPrincipal, UserPrincipal
from threatsculpt.config import Settings
from threatsculpt.core.errors import AuthenticationError, PermissionDeniedError
from threatsculpt.db.session import bind_scope
from threatsculpt.models.org import Org, OrgStatus
from threatsculpt.models.user import Role
from threatsculpt.security.tokens import AGENT_KEY_PREFIX, JwtCodec, hash_token
from threatsculpt.tenancy import credentials
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

_BEARER_SCHEME = "bearer"


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_jwt_codec(request: Request) -> JwtCodec:
    codec: JwtCodec = request.app.state.jwt_codec
    return codec


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """One session and one transaction per request.

    Commits on a clean return, rolls back on any exception. Because the scope
    GUC is transaction-local, commit is also what releases it.
    """
    factory = request.app.state.session_factory
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()


SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


def bearer_credential(request: Request) -> str:
    header = request.headers.get("authorization")
    if not header:
        raise AuthenticationError("Missing Authorization header.")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != _BEARER_SCHEME or not value.strip():
        raise AuthenticationError("Authorization header must be 'Bearer <token>'.")
    return value.strip()


async def current_user(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    codec: Annotated[JwtCodec, Depends(get_jwt_codec)],
) -> UserPrincipal:
    """Authenticate a dashboard caller and bind the request's tenant scope."""
    token = bearer_credential(request)
    if token.startswith(AGENT_KEY_PREFIX):
        # An agent key is not a weaker user token; it is a different credential
        # system. Reject before any lookup so the two never meet.
        raise AuthenticationError("This credential cannot be used on dashboard routes.")

    claims = codec.decode(token)

    # The org comes from the signed token, never from the request body or query.
    await bind_scope(session, OrgScope.for_system(claims.org_id))

    user = await credentials.find_user_by_id(session, claims.user_id)
    if user is None or user.org_id != claims.org_id or not user.is_active:
        raise AuthenticationError("Access token is invalid or expired.")
    if user.role != claims.role:
        # Role changed after the token was minted; make the caller re-authenticate
        # rather than honour a stale privilege level for up to 15 minutes.
        raise AuthenticationError("Access token is invalid or expired.")

    await _assert_org_active(session, claims.org_id)

    scope = OrgScope.for_user(user)
    await bind_scope(session, scope)  # same org, now with a concrete actor
    request.state.org_id = str(scope.org_id)
    request.state.actor_id = str(user.id)
    return UserPrincipal(user=user, scope=scope)


async def current_agent(
    request: Request,
    session: SessionDep,
) -> AgentPrincipal:
    """Authenticate a scan agent by API key.

    Built here for the agent routes another agent will add on top; this module
    owns the verification, not the endpoints.
    """
    presented = bearer_credential(request)
    if not presented.startswith(AGENT_KEY_PREFIX):
        raise AuthenticationError("Agent routes require an agent API key.")

    agent = await credentials.find_agent_by_key_hash(session, hash_token(presented))
    if agent is None:
        raise AuthenticationError("Agent API key is invalid or revoked.")

    scope = OrgScope.for_agent(agent)
    await bind_scope(session, scope)
    await _assert_org_active(session, scope.org_id)

    request.state.org_id = str(scope.org_id)
    request.state.actor_id = str(agent.id)
    return AgentPrincipal(agent=agent, scope=scope)


async def _assert_org_active(session: AsyncSession, org_id: object) -> None:
    """A suspended org authenticates nobody.

    ``orgs`` is not tenant-scoped (it *is* the tenant), so this is a plain read.
    """
    org = await session.get(Org, org_id)
    if org is None or org.status != OrgStatus.ACTIVE.value:
        raise AuthenticationError("This organisation is not active.")


CurrentUser = Annotated[UserPrincipal, Depends(current_user)]
CurrentAgent = Annotated[AgentPrincipal, Depends(current_agent)]


def require_role(minimum: Role | str) -> Callable[[UserPrincipal], Awaitable[UserPrincipal]]:
    """Route dependency enforcing ``owner > admin > analyst > viewer``.

    Used as an explicit dependency on the route, so the required role is visible
    in the route definition and in the generated OpenAPI schema rather than
    buried in a handler body.
    """
    required = minimum.value if isinstance(minimum, Role) else str(minimum)
    if required not in {role.value for role in Role}:
        raise ValueError(f"unknown role: {required!r}")

    async def _dependency(principal: CurrentUser) -> UserPrincipal:
        if not principal.has_role(required):
            raise PermissionDeniedError(f"This action requires the '{required}' role or higher.")
        return principal

    _dependency.__name__ = f"require_role_{required}"
    return _dependency


RequireViewer = Annotated[UserPrincipal, Depends(require_role(Role.VIEWER))]
RequireAnalyst = Annotated[UserPrincipal, Depends(require_role(Role.ANALYST))]
RequireAdmin = Annotated[UserPrincipal, Depends(require_role(Role.ADMIN))]
RequireOwner = Annotated[UserPrincipal, Depends(require_role(Role.OWNER))]
