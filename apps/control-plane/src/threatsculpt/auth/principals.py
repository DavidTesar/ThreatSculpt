"""Authenticated principal value objects.

Two types, no common base with behaviour. A function that accepts a
``UserPrincipal`` cannot be handed an ``AgentPrincipal`` and vice versa — the
separation docs/ARCHITECTURE.md requires is expressed in the type, not in a role
check inside a shared object.
"""

from __future__ import annotations

from dataclasses import dataclass

from threatsculpt.models.agent import Agent
from threatsculpt.models.user import User
from threatsculpt.tenancy.scope import OrgScope


@dataclass(frozen=True, slots=True)
class UserPrincipal:
    """A dashboard caller: a human, authenticated by JWT."""

    user: User
    scope: OrgScope

    @property
    def role(self) -> str:
        return self.user.role

    def has_role(self, required: str) -> bool:
        return self.user.has_role(required)


@dataclass(frozen=True, slots=True)
class AgentPrincipal:
    """A scan agent: a machine, authenticated by API key.

    Deliberately has no ``role`` and no ``has_role``. An agent is not a weak
    user; it can claim jobs for its org and submit results for those jobs, and
    the RBAC ladder does not apply to it at all.
    """

    agent: Agent
    scope: OrgScope
