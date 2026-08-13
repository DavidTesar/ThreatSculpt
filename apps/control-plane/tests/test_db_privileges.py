"""The superuser foot-gun: startup refusal, and a loud migration 0003.

The failure these guard against has no symptom. A role with SUPERUSER or
BYPASSRLS makes PostgreSQL ignore every RLS policy silently, so the service
keeps serving traffic while layer 3 of tenancy isolation has stopped existing.
Both halves are therefore tested for the *refusal*, not just the happy path.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager

import pytest
from alembic import command
from alembic.config import Config
from pydantic import SecretStr
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import APP_ROLE, PROJECT_ROOT, TEST_JWT_SECRET, _sync_url, admin_url
from threatsculpt.app import create_app
from threatsculpt.config import Settings
from threatsculpt.db.engine import build_engine
from threatsculpt.db.privileges import (
    ESCAPE_HATCH_ENV_VAR,
    InsecureDatabaseRoleError,
    assert_database_role_is_unprivileged,
    read_role_privileges,
)


@pytest.fixture
def superuser_settings(settings: Settings) -> Settings:
    """Settings pointed at the owner DSN, which is a superuser in this fixture.

    ``SecretStr`` is applied by hand because ``model_copy(update=...)`` assigns
    without validating, which would leave a bare ``str`` where the rest of the
    code expects a secret wrapper.
    """
    return settings.model_copy(update={"database_url": SecretStr(admin_url())})


@pytest.fixture
async def superuser_engine(superuser_settings: Settings) -> AsyncIterator[AsyncEngine]:
    engine = build_engine(superuser_settings)
    try:
        yield engine
    finally:
        await engine.dispose()


# --- the premise --------------------------------------------------------------


async def test_the_two_roles_differ_as_the_suite_assumes(
    app_engine: AsyncEngine, superuser_engine: AsyncEngine
) -> None:
    """Guards the fixtures themselves: if both roles were equal, nothing below tests anything."""
    application = await read_role_privileges(app_engine)
    owner = await read_role_privileges(superuser_engine)

    assert application.role_name == APP_ROLE
    assert application.bypasses_row_level_security is False
    assert owner.bypasses_row_level_security is True


# --- startup assertion --------------------------------------------------------


async def test_unprivileged_role_passes_the_check(app_engine: AsyncEngine) -> None:
    privileges = await assert_database_role_is_unprivileged(app_engine)

    assert privileges.role_name == APP_ROLE


async def test_privileged_role_is_refused(superuser_engine: AsyncEngine) -> None:
    with pytest.raises(InsecureDatabaseRoleError) as raised:
        await assert_database_role_is_unprivileged(superuser_engine)

    message = str(raised.value)
    assert "SUPERUSER" in message
    assert "bootstrap_db.sql" in message
    assert ESCAPE_HATCH_ENV_VAR in message


@contextmanager
def capturing(logger_name: str) -> Iterator[list[logging.LogRecord]]:
    """Capture records from one logger, independently of root handlers.

    ``caplog`` cannot be used here: the session-scoped database fixture runs
    Alembic in-process, and ``migrations/env.py`` calls ``logging.config
    .fileConfig``, which tears down existing root handlers — pytest's capture
    handler among them. Attaching directly to the logger under test sidesteps
    that entirely.
    """
    records: list[logging.LogRecord] = []

    class Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger(logger_name)
    handler = Collector(level=logging.DEBUG)
    previous_level, previous_propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate


async def test_escape_hatch_permits_a_privileged_role(superuser_engine: AsyncEngine) -> None:
    """Allowed, but never quietly: an override left on must be visible."""
    with capturing("threatsculpt.db.privileges") as records:
        privileges = await assert_database_role_is_unprivileged(
            superuser_engine, allow_superuser=True
        )

    assert privileges.bypasses_row_level_security is True
    critical = [record for record in records if record.levelno == logging.CRITICAL]
    assert critical, "an RLS bypass must be logged at CRITICAL on every boot"
    assert "RLS BYPASSED" in critical[0].getMessage()


async def test_a_clean_boot_does_not_log_a_bypass(app_engine: AsyncEngine) -> None:
    """The CRITICAL line must mean something: it must not fire on the good path."""
    with capturing("threatsculpt.db.privileges") as records:
        await assert_database_role_is_unprivileged(app_engine)

    assert [record for record in records if record.levelno >= logging.WARNING] == []


async def test_the_escape_hatch_is_off_by_default() -> None:
    """The safe value must be the one you get by not thinking about it."""
    settings = Settings(
        database_url="postgresql://u:p@h/d",
        jwt_secret=TEST_JWT_SECRET,
        _env_file=None,
    )

    assert settings.allow_superuser_db is False


def test_the_escape_hatch_reads_its_environment_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TS_DATABASE_URL", "postgresql://u:p@h/d")
    monkeypatch.setenv("TS_JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setenv(ESCAPE_HATCH_ENV_VAR, "1")

    assert Settings(_env_file=None).allow_superuser_db is True


# --- the same thing, through a real application boot --------------------------


async def test_the_app_refuses_to_boot_on_a_privileged_role(
    superuser_settings: Settings,
) -> None:
    """End to end: lifespan raises, so the process exits non-zero."""
    app = create_app(superuser_settings)

    with pytest.raises(InsecureDatabaseRoleError):
        async with app.router.lifespan_context(app):
            pass  # pragma: no cover - startup must not get this far


async def test_the_app_boots_on_the_unprivileged_role(settings: Settings) -> None:
    app = create_app(settings)

    async with app.router.lifespan_context(app):
        assert app.state.session_factory is not None


async def test_the_app_boots_on_a_privileged_role_when_opted_in(
    superuser_settings: Settings,
) -> None:
    app = create_app(superuser_settings.model_copy(update={"allow_superuser_db": True}))

    async with app.router.lifespan_context(app):
        assert app.state.session_factory is not None


# --- migration 0003 -----------------------------------------------------------


@pytest.fixture
def scratch_database() -> Iterator[str]:
    """A throwaway database, so migration tests cannot disturb the suite's schema."""
    name = f"ts_probe_{uuid.uuid4().hex[:12]}"
    admin = create_engine(_sync_url(admin_url()), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    admin.dispose()

    scheme, _, rest = admin_url().partition("://")
    _, _, tail = rest.rpartition("@") if "@" in rest else ("", "", rest)
    credentials = rest.rpartition("@")[0]
    host_part = tail.split("/", 1)[1] if "/" in tail else tail
    query = f"?{host_part.split('?', 1)[1]}" if "?" in host_part else ""
    host = tail.split("/", 1)[0]
    prefix = f"{credentials}@" if credentials else ""
    yield f"{scheme}://{prefix}{host}/{name}{query}"

    admin = create_engine(_sync_url(admin_url()), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = :n AND pid <> pg_backend_pid()"
            ),
            {"n": name},
        )
        connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
    admin.dispose()


def _alembic_config(url: str, *extra: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.cmd_opts = type("Opts", (), {"x": [f"url={url}", *extra]})()
    return config


def test_migration_0003_fails_when_the_app_role_is_missing(scratch_database: str) -> None:
    """A silent no-op here is what pushes an operator toward the superuser DSN."""
    config = _alembic_config(scratch_database, "app_role=role_that_does_not_exist")

    with pytest.raises(Exception) as raised:
        command.upgrade(config, "head")

    message = str(raised.value)
    assert "does not exist" in message
    assert "allow_missing_role" in message
    assert "bootstrap_db.sql" in message


def test_migration_0003_warns_against_the_superuser_workaround(
    scratch_database: str,
) -> None:
    """The error must name the trap, not just the missing role."""
    config = _alembic_config(scratch_database, "app_role=role_that_does_not_exist")

    with pytest.raises(Exception) as raised:
        command.upgrade(config, "head")

    assert "BYPASSRLS" in str(raised.value)


def test_migration_0003_skips_when_explicitly_allowed(scratch_database: str) -> None:
    config = _alembic_config(
        scratch_database, "app_role=role_that_does_not_exist", "allow_missing_role=1"
    )

    command.upgrade(config, "head")

    engine = create_engine(_sync_url(scratch_database))
    with engine.connect() as connection:
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    engine.dispose()
    assert version is not None


def test_migration_0003_grants_when_the_role_exists(scratch_database: str) -> None:
    config = _alembic_config(scratch_database, f"app_role={APP_ROLE}")

    command.upgrade(config, "head")

    engine = create_engine(_sync_url(scratch_database))
    with engine.connect() as connection:
        granted = connection.execute(
            text(
                "SELECT count(DISTINCT table_name) FROM information_schema.role_table_grants "
                "WHERE grantee = :role"
            ),
            {"role": APP_ROLE},
        ).scalar_one()
        audit_privileges = {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE grantee = :role AND table_name = 'audit_log'"
                ),
                {"role": APP_ROLE},
            ).all()
        }
    engine.dispose()

    assert granted > 0
    assert audit_privileges == {"SELECT", "INSERT"}, "audit_log must stay append-only"
