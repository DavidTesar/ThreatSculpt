"""A locked account must not answer faster than any other rejection.

``_record_failure``'s docstring claims lockout state is not observable to an
attacker probing for valid addresses. It was: the locked branch skipped Argon2
entirely and wrote nothing, so it replied in a fraction of the time of either
other outcome, with no overlap between the distributions at all. Ten guesses and
one stopwatch then confirmed an address was real.

Wall-clock assertions are flaky under a shared CI runner, so these count the work
instead — the Argon2 verifications and the bookkeeping transaction are what the
clock was measuring.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.factories import API, register_tenant
from threatsculpt.app import create_app
from threatsculpt.config import Settings
from threatsculpt.db.engine import build_engine, build_session_factory
from threatsculpt.security import passwords

MAX_FAILURES = 3


@pytest.fixture
def argon2_calls(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Count the Argon2 verifications the login path spends.

    Every path goes through ``verify_password`` — ``burn_dummy_verification`` is
    a call to it against a hash nobody holds — so one counter covers real
    verifications and timing-equalising ones alike, which is the point: they are
    supposed to be indistinguishable.
    """
    calls: list[str] = []
    real_verify = passwords.verify_password

    def counted_verify(password: str, password_hash: str) -> bool:
        calls.append(password_hash)
        return real_verify(password, password_hash)

    monkeypatch.setattr(passwords, "verify_password", counted_verify)
    yield calls


@pytest.fixture
async def strict_app(settings: Settings) -> AsyncIterator[FastAPI]:
    tightened = settings.model_copy(
        update={"max_failed_logins": MAX_FAILURES, "login_lockout_minutes": 15}
    )
    application = create_app(tightened)
    engine = build_engine(tightened)
    application.state.engine = engine
    application.state.session_factory = build_session_factory(engine)
    try:
        yield application
    finally:
        await engine.dispose()


@pytest.fixture
async def strict_client(strict_app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=strict_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def _lock_out(client: AsyncClient, email: str) -> None:
    for index in range(MAX_FAILURES):
        response = await client.post(
            f"{API}/auth/login", json={"email": email, "password": f"wrong-guess-{index}"}
        )
        assert response.status_code == 401


async def test_an_unknown_address_spends_one_argon2_verification(
    strict_client: AsyncClient, argon2_calls: list[str]
) -> None:
    argon2_calls.clear()

    await strict_client.post(
        f"{API}/auth/login", json={"email": "nobody@nowhere.example", "password": "whatever-it-is"}
    )

    assert len(argon2_calls) == 1


async def test_a_wrong_password_spends_one_argon2_verification(
    strict_client: AsyncClient, argon2_calls: list[str]
) -> None:
    tenant = await register_tenant(strict_client, "acme")
    argon2_calls.clear()

    await strict_client.post(
        f"{API}/auth/login", json={"email": tenant.email, "password": "definitely-wrong"}
    )

    assert len(argon2_calls) == 1


async def test_a_locked_account_spends_the_same_argon2_verification(
    strict_client: AsyncClient, argon2_calls: list[str]
) -> None:
    """The branch that used to answer in a fraction of the time."""
    tenant = await register_tenant(strict_client, "acme")
    await _lock_out(strict_client, tenant.email)
    argon2_calls.clear()

    response = await strict_client.post(
        f"{API}/auth/login", json={"email": tenant.email, "password": tenant.password}
    )

    assert response.status_code == 401
    assert len(argon2_calls) == 1


async def test_an_attempt_against_a_locked_account_is_still_audited(
    strict_client: AsyncClient, strict_app: FastAPI
) -> None:
    """The SOC signal, and the reason the timing matches: one committed write.

    Somebody still guessing at an account that has already tripped its threshold
    is worth a record; it also gives the locked branch the same database cost as
    the wrong-password branch.
    """
    tenant = await register_tenant(strict_client, "acme")
    await _lock_out(strict_client, tenant.email)

    engine: AsyncEngine = strict_app.state.engine
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        before = int(
            (
                await connection.execute(
                    text(
                        "SELECT count(*) FROM audit_log WHERE org_id = :org "
                        "AND action = 'auth.login_failed'"
                    ),
                    {"org": str(tenant.org_id)},
                )
            ).scalar_one()
        )

    await strict_client.post(
        f"{API}/auth/login", json={"email": tenant.email, "password": "one-more-guess"}
    )

    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        after = int(
            (
                await connection.execute(
                    text(
                        "SELECT count(*) FROM audit_log WHERE org_id = :org "
                        "AND action = 'auth.login_failed'"
                    ),
                    {"org": str(tenant.org_id)},
                )
            ).scalar_one()
        )

    assert after == before + 1


async def test_guessing_at_a_locked_account_does_not_extend_the_lockout(
    strict_client: AsyncClient, strict_app: FastAPI
) -> None:
    """A stranger who can renew a lockout indefinitely has a permanent denial."""
    tenant = await register_tenant(strict_client, "acme")
    await _lock_out(strict_client, tenant.email)

    engine: AsyncEngine = strict_app.state.engine

    async def locked_until() -> object:
        async with engine.begin() as connection:
            await connection.execute(
                text("SELECT set_config('threatsculpt.org_id', :org, true)"),
                {"org": str(tenant.org_id)},
            )
            return (
                await connection.execute(
                    text("SELECT locked_until FROM users WHERE id = :uid"),
                    {"uid": tenant.user_id},
                )
            ).scalar_one()

    original = await locked_until()
    for _ in range(5):
        await strict_client.post(
            f"{API}/auth/login", json={"email": tenant.email, "password": "keep-guessing"}
        )

    assert await locked_until() == original
