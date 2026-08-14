"""Test fixtures.

The important structural choice here: the application connects as a
NOSUPERUSER / NOBYPASSRLS role, while migrations and fixture cleanup run as the
owner. Testing RLS from a superuser connection proves nothing — a superuser
bypasses every policy — so the suite would happily pass with the whole of
migration 0002 deleted.

Point ``TS_TEST_ADMIN_DATABASE_URL`` (or ``DATABASE_URL``, which CI injects) at a
DSN with rights to create roles and run DDL, on a database you do not mind
having truncated.

The application role's name is **derived from the database name**, not fixed. A
PostgreSQL role is cluster-wide while a test database is not, so a single shared
role name means two suites running against two different databases on one
cluster still rotate each other's password at session start — the second one to
start locks the first one out mid-run, and the failures land as
``password authentication failed`` on whichever pooled connection opens next.
That is a genuinely confusing way to lose an afternoon, and it costs one derived
identifier to rule out. It matters for concurrent local work and for any CI that
runs a matrix of jobs against one PostgreSQL service.

If a DSN was configured but the database is unreachable, the suite **fails**
rather than skipping. A silent skip is the worst outcome here: CI would report
green while every cross-tenant isolation test — the reason this suite exists —
had quietly not run.
"""

from __future__ import annotations

import os
import re
import secrets
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from urllib.parse import quote, urlsplit

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from tests.network_guard import block_outbound_network
from threatsculpt.app import create_app
from threatsculpt.config import Settings
from threatsculpt.db.dsn import dsn_from_environment
from threatsculpt.db.engine import build_engine, build_session_factory

PROJECT_ROOT = Path(__file__).resolve().parents[1]

APP_ROLE_PREFIX = "threatsculpt_app"

#: PostgreSQL identifiers are truncated at 63 bytes; a silently truncated role
#: name would not match the one handed to the migrations.
MAX_ROLE_NAME_LENGTH = 63

#: Used only when nothing is configured, i.e. a developer running the suite on a
#: stock local PostgreSQL.
DEFAULT_ADMIN_URL = "postgresql://postgres@localhost:5432/threatsculpt_test"

ADMIN_DSN_ENV_VAR = "TS_TEST_ADMIN_DATABASE_URL"

TEST_JWT_SECRET = "test-only-jwt-secret-value-that-is-long-enough-01234"

#: Truncated between tests, children first so cascade order is obvious.
_ALL_TABLES = (
    "audit_log",
    "reports",
    "findings",
    "vulnerability_cpe_matches",
    "ports",
    "scan_results",
    "scan_jobs",
    "asset_services",
    "assets",
    "business_services",
    "networks",
    "enrollment_tokens",
    "agents",
    "refresh_tokens",
    "users",
    "vulnerabilities",
    "feed_sync_state",
    "orgs",
)


def admin_url() -> str:
    """Resolve the DSN for the owner connection.

    ``TS_TEST_ADMIN_DATABASE_URL`` first, then ``DATABASE_URL`` — the name CI and
    deploy platforms conventionally inject, and the only one the pipeline sets.
    """
    explicit = os.environ.get(ADMIN_DSN_ENV_VAR, "").strip()
    return explicit or dsn_from_environment() or DEFAULT_ADMIN_URL


def dsn_was_configured() -> bool:
    """True when an operator or CI pointed the suite at a specific database."""
    return admin_url() != DEFAULT_ADMIN_URL


def database_name(url: str) -> str:
    """The database from a DSN, for both the TCP and unix-socket forms."""
    return urlsplit(url).path.lstrip("/")


def app_role_for(url: str) -> str:
    """The application role name for a given test database.

    Sanitised to an identifier: migration 0003 refuses anything that is not
    ``^[A-Za-z_][A-Za-z0-9_]{0,62}$``, and the name is interpolated into DDL
    where bind parameters are not permitted, so this must not be able to carry
    anything but an identifier.
    """
    suffix = re.sub(r"[^a-z0-9_]", "_", database_name(url).lower()).strip("_")
    name = f"{APP_ROLE_PREFIX}_{suffix}" if suffix else APP_ROLE_PREFIX
    return name[:MAX_ROLE_NAME_LENGTH]


#: Resolved once per session, from the database this run was pointed at.
APP_ROLE = app_role_for(admin_url())


def _sync_url(url: str) -> str:
    scheme, _, rest = url.partition("://")
    return f"{scheme.split('+')[0]}+psycopg://{rest}"


def _app_role_url(admin: str, password: str) -> str:
    """Same host and database as the admin DSN, but as the application role."""
    scheme, _, rest = admin.partition("://")
    _, _, host_and_db = rest.rpartition("@") if "@" in rest else ("", "", rest)
    return f"{scheme.split('+')[0]}://{APP_ROLE}:{quote(password)}@{host_and_db}"


@pytest.fixture(autouse=True, scope="session")
def _no_outbound_network() -> Iterator[None]:
    """The suite may talk to this machine and nothing else.

    ``src/`` now contains a real HTTP client (``enrichment.http``), so "there is
    no way to reach the network from here" has to be enforced rather than
    observed. See ``tests/network_guard`` for what is still allowed and why, and
    ``tests/test_enrichment_no_network.py`` for the proof that this bites.
    """
    with block_outbound_network():
        yield


@pytest.fixture(scope="session")
def database(request: pytest.FixtureRequest) -> Iterator[str]:
    """Provision the app role, migrate, and yield the application DSN."""
    password = secrets.token_urlsafe(24)
    admin = admin_url()
    engine = create_engine(_sync_url(admin), isolation_level="AUTOCOMMIT")

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        engine.dispose()
        if dsn_was_configured() or os.environ.get("CI"):
            # Somebody meant for this to work. Skipping would turn a broken
            # database into a green build with 135 tests silently not run.
            pytest.fail(f"configured test database at {admin!r} is unreachable: {exc}")
        pytest.skip(  # pragma: no cover - only hit on an unconfigured workstation
            f"no test database at {admin!r} and none configured via {ADMIN_DSN_ENV_VAR}: {exc}"
        )

    with engine.connect() as connection:
        exists = connection.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": APP_ROLE}
        ).first()
        verb = "ALTER" if exists else "CREATE"
        connection.execute(text(f"{verb} ROLE {APP_ROLE} LOGIN PASSWORD '{password}'"))
        connection.execute(
            text(f"ALTER ROLE {APP_ROLE} NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS")
        )

    app_url = _app_role_url(admin, password)

    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.cmd_opts = type("Opts", (), {"x": [f"url={admin}", f"app_role={APP_ROLE}"]})()
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    yield app_url

    engine.dispose()


@pytest.fixture(scope="session")
def settings(database: str) -> Settings:
    return Settings(
        environment="test",
        database_url=database,
        db_app_role=APP_ROLE,
        jwt_secret=TEST_JWT_SECRET,
        cookie_secure=False,
        cors_origins=("http://testserver",),
        log_json=False,
        log_level="WARNING",
        auth_rate_limit_per_minute=1000,
        general_rate_limit_per_minute=1000,
        anonymous_rate_limit_per_minute=1000,
        # There is no mail infrastructure here, so the suite reads the
        # verification token out of the in-process sender instead. The flow
        # under test is the real one; only delivery is a stand-in.
        email_delivery="memory",
        # Nothing here delivers mail, so the boot check would refuse to start.
        # Declared explicitly rather than inferred from environment="test", so
        # running without delivery is always a deliberate act.
        allow_undeliverable_email=True,
    )


@pytest.fixture(autouse=True)
def _clean_tables(database: str) -> Iterator[None]:
    """Truncate as the owner between tests; the app role may not TRUNCATE audit_log."""
    engine = create_engine(_sync_url(admin_url()), isolation_level="AUTOCOMMIT")
    with engine.connect() as connection:
        connection.execute(text(f"TRUNCATE {', '.join(_ALL_TABLES)} RESTART IDENTITY CASCADE"))
    engine.dispose()
    yield


@pytest_asyncio.fixture
async def app(settings: Settings) -> AsyncIterator[object]:
    application = create_app(settings)
    engine = build_engine(settings)
    application.state.engine = engine
    application.state.session_factory = build_session_factory(engine)
    try:
        yield application
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def client(app: object) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


@pytest_asyncio.fixture
async def session_factory(app: object) -> async_sessionmaker[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = app.state.session_factory  # type: ignore[attr-defined]
    return factory


@pytest_asyncio.fixture
async def app_engine(app: object) -> AsyncEngine:
    """The application's own engine — the non-superuser connection.

    Used by the RLS tests to issue raw SQL under a chosen ``threatsculpt.org_id``,
    bypassing every Python-side control so that only the database's answer is
    under test.
    """
    engine: AsyncEngine = app.state.engine  # type: ignore[attr-defined]
    return engine
