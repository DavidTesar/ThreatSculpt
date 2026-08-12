"""Alembic environment.

Resolves its database URL on its own — it never constructs the application
``Settings``. Applying the schema is a database operation, so it needs a DSN and
nothing else; requiring the JWT signing secret to run a migration would spread
that secret to every migration runner and deploy job for no benefit.

Resolution order, first match wins:

1. ``-x url=…`` on the command line
2. ``TS_DATABASE_URL``   (project convention)
3. ``DATABASE_URL``      (what CI and deploy platforms conventionally inject)
4. ``sqlalchemy.url`` in ``alembic.ini`` (unset by default — a DSN carries a
   password and does not belong in a tracked file)

Migrations should be applied by a role that owns the tables. The application
connects as a separate, non-superuser role so that RLS actually applies to it.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from threatsculpt.db.dsn import (  # noqa: E402
    DSN_ENV_VARS,
    dsn_from_environment,
    normalise_driver,
)
from threatsculpt.models import Base  # noqa: E402  (registers every mapper)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

DEFAULT_APP_ROLE = "threatsculpt_app"


def _x_argument(name: str) -> str | None:
    value = context.get_x_argument(as_dictionary=True).get(name)
    return value.strip() if value else None


def database_url() -> str:
    """The DSN to migrate, normalised onto psycopg3."""
    candidate = (
        _x_argument("url")
        or dsn_from_environment()
        or config.get_main_option("sqlalchemy.url", None)
    )
    if not candidate:
        raise RuntimeError(
            "No database URL. Set one of "
            f"{' or '.join(DSN_ENV_VARS)}, pass -x url=…, or set sqlalchemy.url "
            "in alembic.ini."
        )
    return normalise_driver(candidate)


def app_role() -> str:
    """Role the grants migration targets. ``-x app_role=`` wins over the env."""
    return _x_argument("app_role") or os.environ.get("TS_DB_APP_ROLE", DEFAULT_APP_ROLE)


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
