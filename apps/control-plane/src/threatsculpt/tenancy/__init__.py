"""Tenancy enforcement: scopes, the ORM guard, and scoped repositories."""

from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import ActorType, OrgScope

__all__ = ["ActorType", "OrgScope", "ScopedRepository"]
