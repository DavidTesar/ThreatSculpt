"""The only supported way to reach a tenant table.

Every statement built here carries ``WHERE org_id = :scope`` *and* the execution
option the guard demands. A caller cannot obtain a repository without first
producing an ``OrgScope``, and cannot produce an ``OrgScope`` without an
authenticated principal — so "read another org's row" has no expressible form.

Note on mutation: an ORM identity-mapped entity is mutated in place by design;
that is what makes ``UPDATE`` work. The immutable-style rule is honoured where
it is meaningful — scopes, pages, filters and DTOs are frozen, and ``update``
takes a dict of validated changes rather than letting callers poke attributes
from arbitrary places.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import CursorResult, Select, delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from threatsculpt.core.errors import ConflictError, NotFoundError, TenancyViolationError
from threatsculpt.core.pagination import Page, PaginationParams
from threatsculpt.db.base import TenantModel
from threatsculpt.tenancy.guard import SCOPED_OPTION, bound_scope
from threatsculpt.tenancy.scope import OrgScope


class ScopedRepository[ModelT: TenantModel]:
    """Tenant-scoped data access for one mapped model."""

    def __init__(self, session: AsyncSession, scope: OrgScope, model: type[ModelT]) -> None:
        if not issubclass(model, TenantModel):
            raise TenancyViolationError(
                f"{model.__name__} is not a tenant model; use a plain session for it"
            )
        session_scope = bound_scope(session)
        if session_scope is None or session_scope.org_id != scope.org_id:
            raise TenancyViolationError(
                "repository scope does not match the scope bound to the session"
            )
        self._session: AsyncSession = session
        self._scope: OrgScope = scope
        self._model: type[ModelT] = model

    @property
    def scope(self) -> OrgScope:
        return self._scope

    @property
    def model(self) -> type[ModelT]:
        return self._model

    # --- query construction ------------------------------------------------

    def select(self, *criteria: ColumnElement[bool]) -> Select[tuple[ModelT]]:
        """A SELECT already narrowed to this org and stamped for the guard."""
        return (
            select(self._model)
            .where(self._org_predicate(), *criteria)
            .execution_options(**self._scoped_options())
        )

    def _org_predicate(self) -> ColumnElement[bool]:
        return self._model.org_id == self._scope.org_id

    def _scoped_options(self) -> dict[str, Any]:
        """The execution option the guard requires. Its value is this org's id."""
        return {SCOPED_OPTION: self._scope.org_id}

    # --- reads -------------------------------------------------------------

    async def get(self, entity_id: UUID) -> ModelT | None:
        result = await self._session.execute(self.select(self._model.id == entity_id))
        return result.scalar_one_or_none()

    async def get_or_404(self, entity_id: UUID) -> ModelT:
        """Missing and belongs-to-another-org are the same answer, by design."""
        entity = await self.get(entity_id)
        if entity is None:
            raise NotFoundError()
        return entity

    async def find_one(self, *criteria: ColumnElement[bool]) -> ModelT | None:
        result = await self._session.execute(self.select(*criteria).limit(2))
        rows = result.scalars().all()
        if len(rows) > 1:
            raise ConflictError("More than one row matched a lookup expected to be unique.")
        return rows[0] if rows else None

    async def list(
        self,
        pagination: PaginationParams,
        *criteria: ColumnElement[bool],
        order_by: Sequence[ColumnElement[Any]] | None = None,
    ) -> Page[ModelT]:
        """Always bounded: ``pagination`` is required, not optional."""
        statement = self.select(*criteria)
        if order_by:
            statement = statement.order_by(*order_by)
        statement = statement.limit(pagination.limit).offset(pagination.offset)

        rows = (await self._session.execute(statement)).scalars().all()
        total = await self.count(*criteria)
        return Page(items=tuple(rows), total=total, params=pagination)

    async def count(self, *criteria: ColumnElement[bool]) -> int:
        statement = (
            select(func.count())
            .select_from(self._model)
            .where(self._org_predicate(), *criteria)
            .execution_options(**self._scoped_options())
        )
        result = await self._session.execute(statement)
        return int(result.scalar_one())

    async def exists(self, *criteria: ColumnElement[bool]) -> bool:
        return await self.count(*criteria) > 0

    # --- writes ------------------------------------------------------------

    async def create(self, **values: Any) -> ModelT:
        """``org_id`` is set from the scope and cannot be supplied by the caller."""
        if "org_id" in values:
            raise TenancyViolationError("org_id is derived from the scope, never passed in")
        entity = self._model(org_id=self._scope.org_id, **values)
        self._session.add(entity)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            raise ConflictError("The record conflicts with an existing one.") from exc
        return entity

    async def update(self, entity: ModelT, changes: dict[str, Any]) -> ModelT:
        """Apply validated ``changes`` to an entity this scope already fetched."""
        self._assert_owned(entity)
        if "org_id" in changes or "id" in changes:
            raise TenancyViolationError("org_id and id are not updatable")
        for field, value in changes.items():
            setattr(entity, field, value)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            raise ConflictError("The update conflicts with an existing record.") from exc
        return entity

    async def update_where(self, changes: dict[str, Any], *criteria: ColumnElement[bool]) -> int:
        """Bulk UPDATE, still fenced by the org predicate. Returns rows affected."""
        if "org_id" in changes or "id" in changes:
            raise TenancyViolationError("org_id and id are not updatable")
        statement = (
            update(self._model)
            .where(self._org_predicate(), *criteria)
            .values(**changes)
            .execution_options(**self._scoped_options())
        )
        return _rows_affected(await self._session.execute(statement))

    async def delete(self, entity: ModelT) -> None:
        self._assert_owned(entity)
        await self._session.delete(entity)
        await self._session.flush()

    async def delete_where(self, *criteria: ColumnElement[bool]) -> int:
        statement = (
            delete(self._model)
            .where(self._org_predicate(), *criteria)
            .execution_options(**self._scoped_options())
        )
        return _rows_affected(await self._session.execute(statement))

    def _assert_owned(self, entity: ModelT) -> None:
        entity_org = getattr(entity, "org_id", None)
        if entity_org != self._scope.org_id:
            # Reachable only if an entity crossed scopes in memory. Treat it as
            # a not-found rather than confirming the row exists.
            raise NotFoundError()


def _rows_affected(result: object) -> int:
    """Rows touched by an UPDATE/DELETE.

    ``AsyncSession.execute`` is typed as returning ``Result``; only the
    ``CursorResult`` it actually returns for DML carries ``rowcount``.
    """
    if isinstance(result, CursorResult):
        return int(result.rowcount or 0)
    return 0
