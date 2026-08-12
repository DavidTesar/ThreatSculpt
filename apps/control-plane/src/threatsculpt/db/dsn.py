"""DSN resolution, with no dependency on application settings.

Deliberately its own module. Running a schema migration must not require the
application's configuration — a migration job or a DBA should be able to apply
the schema with a database URL and nothing else. Coupling migrations to
``Settings`` would mean handing a migration runner the JWT signing secret, which
is exactly the sort of unnecessary secret spread this rewrite exists to avoid.

So ``migrations/env.py`` imports from here, not from ``threatsculpt.config``,
and this module imports nothing beyond the standard library.
"""

from __future__ import annotations

import os

DEFAULT_DRIVER = "psycopg"

#: Checked in order. ``TS_DATABASE_URL`` is the project convention;
#: ``DATABASE_URL`` is what CI systems and deploy platforms conventionally
#: inject, and is accepted so neither has to be translated into the other.
DSN_ENV_VARS: tuple[str, ...] = ("TS_DATABASE_URL", "DATABASE_URL")


def normalise_driver(url: str, driver: str = DEFAULT_DRIVER) -> str:
    """Rewrite a DSN to use ``driver``.

    ``postgresql://…`` and ``postgresql+asyncpg://…`` both become
    ``postgresql+psycopg://…``. Without this, SQLAlchemy falls back to its
    historical psycopg2 default and fails on a driver that is not installed.
    """
    scheme, separator, rest = url.partition("://")
    if not separator:
        raise ValueError("database URL must be a full DSN, e.g. postgresql://user:pw@host/db")
    base = scheme.split("+", maxsplit=1)[0]
    return f"{base}+{driver}://{rest}"


def dsn_from_environment(env: dict[str, str] | None = None) -> str | None:
    """First non-empty DSN among ``DSN_ENV_VARS``, or ``None``."""
    source = os.environ if env is None else env
    for name in DSN_ENV_VARS:
        value = source.get(name, "").strip()
        if value:
            return value
    return None
