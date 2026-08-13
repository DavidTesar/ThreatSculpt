"""Reloading an entity after a scoped update.

**This module works around a defect in the foundation and should be deleted once
that defect is fixed.**

``TimestampMixin.updated_at`` carries ``onupdate=func.now()``, a SQL-expression
default. After ``ScopedRepository.update`` flushes, SQLAlchemy cannot know what
the database computed, so it expires the attribute. The next read of
``entity.updated_at`` — which is every response model that includes it — triggers
a lazy refresh, and that refresh is an ORM SELECT with no scoped execution
option, so ``tenancy.guard`` correctly refuses it and the request 500s.

The same defect is reachable through ``PATCH /api/v1/networks/{id}``: any
*successful* update of a network fails this way. No existing test performs a
successful PATCH, which is why it had not surfaced.

The real fix belongs in ``ScopedRepository.update`` — it should return an entity
with no expired attributes, e.g. by re-selecting through its own scoped path or
by using ``RETURNING``. Until then this does that re-select explicitly, through
the repository, so the read stays scoped.
"""

from __future__ import annotations

from threatsculpt.db.base import TenantModel
from threatsculpt.tenancy.repository import ScopedRepository


async def reloaded[ModelT: TenantModel](
    repository: ScopedRepository[ModelT], entity: ModelT
) -> ModelT:
    """Re-read ``entity`` through its scoped repository, populating expired columns."""
    return await repository.get_or_404(entity.id)
