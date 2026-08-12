"""``OrgScope`` — the authenticated principal's tenant, as a value object.

A scope is the *only* way to reach a tenant table (see ``guard.py`` and
``repository.py``). It is deliberately not constructible from request data: the
factories below take an already-authenticated principal, so there is no code
shape that turns a client-supplied ``orgId`` into a scope.

The v1 defect this rules out is ``POST /getUserData {userID}`` — a request body
naming whose data to return.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, types only
    from threatsculpt.models.agent import Agent
    from threatsculpt.models.user import User

GUC_NAME = "threatsculpt.org_id"


class ActorType(StrEnum):
    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class OrgScope:
    """Immutable tenant scope carried through the request.

    ``actor_id`` is informational (it feeds the audit log); ``org_id`` is the
    value that constrains every query.
    """

    org_id: UUID
    actor_type: ActorType
    actor_id: UUID | None

    @classmethod
    def for_user(cls, user: User) -> OrgScope:
        return cls(org_id=user.org_id, actor_type=ActorType.USER, actor_id=user.id)

    @classmethod
    def for_agent(cls, agent: Agent) -> OrgScope:
        return cls(org_id=agent.org_id, actor_type=ActorType.AGENT, actor_id=agent.id)

    @classmethod
    def for_system(cls, org_id: UUID) -> OrgScope:
        """Scope for work with no human principal.

        Legitimate uses are narrow and each should say why it is one:
        registration (the org exists but its first user does not yet), the lease
        sweeper, and background enrichment. It is not a general escape hatch —
        it still pins every query to exactly one org.
        """
        return cls(org_id=org_id, actor_type=ActorType.SYSTEM, actor_id=None)

    def guc_value(self) -> str:
        return str(self.org_id)

    def owns(self, org_id: UUID) -> bool:
        return self.org_id == org_id
