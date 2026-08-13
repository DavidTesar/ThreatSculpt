"""The derived application-role name.

Small surface, but it feeds two things that punish a wrong value: DDL string
interpolation in migrations 0003 and 0005 (where bind parameters are not
permitted), and the DSN the application connects with. So the sanitisation is
tested rather than assumed.
"""

from __future__ import annotations

import re

import pytest

from tests.conftest import (
    APP_ROLE,
    APP_ROLE_PREFIX,
    MAX_ROLE_NAME_LENGTH,
    app_role_for,
    database_name,
)

#: The identifier shape migration 0003 enforces.
ROLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")

SOCKET_DSN = "postgresql://postgres@/threatsculpt_test?host=/tmp/sock&port=55432"
TCP_DSN = "postgresql://postgres@localhost:5432/threatsculpt_test"


@pytest.mark.parametrize("dsn", [SOCKET_DSN, TCP_DSN, "postgresql+psycopg://u:p@h:5432/db_one"])
def test_database_name_is_read_from_both_dsn_forms(dsn: str) -> None:
    assert database_name(dsn) in {"threatsculpt_test", "db_one"}


def test_two_databases_get_two_roles() -> None:
    """The whole point: concurrent suites must not share one cluster-wide role."""
    first = app_role_for("postgresql://postgres@localhost:5432/threatsculpt_test")
    second = app_role_for("postgresql://postgres@localhost:5432/threatsculpt_test_agent")
    assert first != second


def test_the_same_database_always_yields_the_same_role() -> None:
    """It is created once and reused; a drifting name would orphan its grants."""
    assert app_role_for(SOCKET_DSN) == app_role_for(TCP_DSN)


@pytest.mark.parametrize(
    "dsn",
    [
        SOCKET_DSN,
        "postgresql://postgres@localhost:5432/Weird-Name.42",
        "postgresql://postgres@localhost:5432/" + "x" * 90,
        "postgresql://postgres@localhost:5432/",
        "postgresql://postgres@localhost:5432/---",
    ],
)
def test_every_derived_name_is_a_legal_identifier(dsn: str) -> None:
    """It is interpolated into DDL, so it must not be able to carry anything else."""
    role = app_role_for(dsn)
    assert ROLE_NAME.match(role), role
    assert len(role) <= MAX_ROLE_NAME_LENGTH
    assert role.startswith(APP_ROLE_PREFIX)


def test_a_dsn_with_no_database_falls_back_to_the_bare_prefix() -> None:
    assert app_role_for("postgresql://postgres@localhost:5432/") == APP_ROLE_PREFIX


def test_the_running_suite_uses_a_derived_role(settings: object) -> None:
    """Guards the wiring: the role the app connects as is the one that was created."""
    assert ROLE_NAME.match(APP_ROLE)
    assert settings.db_app_role == APP_ROLE  # type: ignore[attr-defined]
