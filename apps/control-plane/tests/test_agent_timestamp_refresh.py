"""The behavioural half of the ``eager_defaults`` invariant.

``tests/test_model_invariants.py::test_every_mapper_fetches_server_defaults_eagerly``
pins the *flag* across the whole mapper registry, and it is a real guard — flipping
a mapper to ``False`` or to the truthy string ``"auto"`` both make it fail.

This file pins the *behaviour* the flag exists to produce, on the exact code path
that produced the incident recorded under "Known unknowns" in the README:
``ScopedRepository.update`` followed by reading ``updated_at`` off the returned
entity, which is what every response schema does via ``model_validate``.

The distinction matters because the flag is a proxy. If a future SQLAlchemy
changes what ``eager_defaults=True`` does, or a deployment target stops
supporting ``UPDATE ... RETURNING``, the flag assertion still passes and only
these tests notice. What must hold is not "the flag is True" but "no lazy
refresh SELECT is emitted after an update" — because that refresh carries no
scope, and ``tenancy.guard`` correctly refuses it.

Note what the failure mode was: the guard **refused an unscoped read**. The
system failed closed. That is the right side of a bad outcome, and it is why
these tests assert on statements emitted rather than on an error not being
raised — a test that only asserts "no exception" would also pass if the guard
were quietly weakened.
"""

from __future__ import annotations

from typing import Any

from httpx import AsyncClient
from sqlalchemy import event, inspect
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from tests.factories import register_tenant
from threatsculpt.db.session import scoped_session
from threatsculpt.models.agent import Agent, AgentStatus
from threatsculpt.security.tokens import (
    AGENT_KEY_PREFIX,
    generate_opaque_token,
    hash_token,
    key_prefix_of,
)
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope


class _StatementRecorder:
    """Records every SQL statement executed on an engine while it is attached."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._sync_engine = engine.sync_engine
        self.statements: list[str] = []

    def _record(self, conn: Any, cursor: Any, statement: str, *args: Any, **kwargs: Any) -> None:
        self.statements.append(statement)

    def __enter__(self) -> _StatementRecorder:
        event.listen(self._sync_engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._sync_engine, "before_cursor_execute", self._record)

    def selects_against(self, table: str) -> list[str]:
        return [
            statement
            for statement in self.statements
            if statement.lstrip().upper().startswith("SELECT") and table in statement
        ]

    def updates_against(self, table: str) -> list[str]:
        return [
            statement
            for statement in self.statements
            if statement.lstrip().upper().startswith("UPDATE") and table in statement
        ]


async def _an_agent(session: AsyncSession, scope: OrgScope) -> Agent:
    key = generate_opaque_token(AGENT_KEY_PREFIX)
    repository = ScopedRepository(session, scope, Agent)
    return await repository.create(
        name="hq-dc-scanner-01",
        api_key_hash=hash_token(key),
        key_prefix=key_prefix_of(key),
        status=AgentStatus.ACTIVE.value,
        version="2.0.0",
        allowlist=["10.0.0.0/8"],
    )


async def test_updating_an_entity_leaves_its_timestamps_loaded(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """The mechanism: after ``update``, no timestamp attribute is expired.

    An expired attribute is what turns the next read into a lazy refresh. If
    nothing is expired, no refresh can be emitted, and the unscoped-SELECT
    failure mode is unreachable rather than merely unobserved.
    """
    tenant = await register_tenant(client, "acme")
    scope = OrgScope.for_system(tenant.org_id)

    async with scoped_session(session_factory, scope) as session:
        agent = await _an_agent(session, scope)
        repository = ScopedRepository(session, scope, Agent)

        updated = await repository.update(agent, {"status": AgentStatus.REVOKED.value})

        unloaded = inspect(updated).unloaded
        assert "updated_at" not in unloaded, (
            "updated_at was expired by the flush; the next read of it will emit an "
            "unscoped lazy-refresh SELECT that the tenancy guard will refuse"
        )
        assert "created_at" not in unloaded


async def test_reading_updated_at_after_an_update_emits_no_refresh_select(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
    app_engine: AsyncEngine,
) -> None:
    """The behaviour, asserted on statements actually sent to the database.

    This is the code path from the README incident: update through the scoped
    repository, then read the timestamps the way ``model_validate`` does.
    """
    tenant = await register_tenant(client, "acme")
    scope = OrgScope.for_system(tenant.org_id)

    async with scoped_session(session_factory, scope) as session:
        agent = await _an_agent(session, scope)
        repository = ScopedRepository(session, scope, Agent)

        with _StatementRecorder(app_engine) as recorder:
            updated = await repository.update(agent, {"status": AgentStatus.REVOKED.value})
            # Exactly what a response schema does.
            _ = updated.updated_at
            _ = updated.created_at

        assert recorder.selects_against("agents") == [], (
            "a SELECT against agents was emitted after the UPDATE — that is the "
            "lazy refresh this invariant exists to prevent"
        )
        statements = recorder.updates_against("agents")
        assert len(statements) == 1, statements
        assert "RETURNING" in statements[0].upper(), (
            f"the UPDATE did not carry RETURNING, so the database-computed "
            f"updated_at cannot have been fetched with it: {statements[0]}"
        )


async def test_the_update_returns_the_value_the_database_computed(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Not merely loaded — loaded with the *new* value.

    A cached stale timestamp would satisfy "not expired" while still being
    wrong. ``updated_at`` must advance past ``created_at``, which only happens
    if the value came back from the UPDATE rather than from the INSERT.
    """
    tenant = await register_tenant(client, "acme")
    scope = OrgScope.for_system(tenant.org_id)

    async with scoped_session(session_factory, scope) as session:
        agent = await _an_agent(session, scope)
        repository = ScopedRepository(session, scope, Agent)
        before = agent.updated_at

        updated = await repository.update(agent, {"status": AgentStatus.REVOKED.value})

        assert updated.updated_at >= before
        assert updated.updated_at >= updated.created_at
        assert updated.status == AgentStatus.REVOKED.value
