"""PostgreSQL column types used across the schema.

Network values are stored as native ``inet``/``cidr``/``macaddr``, never text.
Storing an address as a string throws away the containment operators
(``<<=``) that scan-target validation depends on, and lets
``"10.0.0.1 ; DROP"`` be a legal value.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import types
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, INET, JSONB, MACADDR
from sqlalchemy.dialects.postgresql import UUID as PgUUID  # noqa: N811 - a type, not a constant

__all__ = [
    "ARRAY",
    "CIDR",
    "CITEXT",
    "INET",
    "JSONB",
    "MACADDR",
    "Cidr",
    "Inet",
    "MacAddr",
    "PgUUID",
    "cidr_array",
    "text_array",
]


class _NetworkText(types.TypeDecorator[str]):
    """Native PostgreSQL network column that reads back as ``str``.

    The column really is ``inet``/``cidr``/``macaddr`` — containment operators,
    validation on insert, and index behaviour are all the database's. Only the
    Python-side representation is normalised: psycopg3 hands back
    ``IPv4Network``/``IPv4Address`` objects, and letting those leak into models
    and response schemas would mean every consumer converting them by hand.

    Address *semantics* stay in SQL, where they belong, so nothing is lost by
    carrying the value as text in Python.
    """

    cache_ok = True

    def process_result_value(self, value: object, dialect: object) -> str | None:
        return None if value is None else str(value)


class Cidr(_NetworkText):
    impl = CIDR
    cache_ok = True


class Inet(_NetworkText):
    impl = INET
    cache_ok = True


class MacAddr(_NetworkText):
    impl = MACADDR
    cache_ok = True


class CITEXT(types.UserDefinedType[str]):
    """Case-insensitive text, from the ``citext`` extension.

    Defined here rather than imported so the schema does not depend on a
    third-party package for one type; the extension itself is created by the
    initial migration.
    """

    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:
        return "CITEXT"


def text_array() -> ARRAY:
    return ARRAY(types.Text())


def cidr_array() -> ARRAY:
    return ARRAY(Cidr())
