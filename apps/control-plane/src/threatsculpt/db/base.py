"""Declarative base, shared column mixins, and the tenant-table registry.

``TenantMixin`` is not just a convenience for the ``org_id`` column: subclassing
it is what enrols a table in the tenancy guard (``threatsculpt.tenancy.guard``)
and in the migration that builds RLS policies. A tenant table that forgets the
mixin is a table with no isolation, so the mixin is the single place that
decides "this holds customer data".
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Date, ForeignKey, MetaData, func, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.dialects.postgresql import UUID as PgUUID  # noqa: N811 - a type, not a constant
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s",
    "pk": "pk_%(table_name)s",
}

ORG_ID_COLUMN = "org_id"


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    #: Every ``datetime`` column is ``timestamptz``. A naive timestamp column
    #: silently reinterprets values against the server's TimeZone setting, which
    #: for lease expiry and token expiry means an availability bug in one
    #: direction and a security bug in the other.
    type_annotation_map = {  # noqa: RUF012 - SQLAlchemy requires a plain dict here
        datetime: TIMESTAMP(timezone=True),
        date: Date(),
    }


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )


class UuidPkMixin:
    id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )


class TenantMixin:
    """Marks a table as holding customer data.

    Carries ``org_id NOT NULL REFERENCES orgs(id) ON DELETE CASCADE`` plus its
    index, exactly as docs/DATA-MODEL.md specifies for tables marked **[T]**.
    """

    org_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("orgs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )


class TenantModel(UuidPkMixin, TenantMixin, TimestampMixin, Base):
    """Base class for every table holding customer data.

    Subclassing this is the single act that makes a table tenant-scoped: it
    supplies ``id``, ``org_id`` and the timestamps, enrols the table in the
    tenancy guard, and gives ``ScopedRepository`` a type bound that actually
    guarantees an ``org_id`` column exists rather than trusting the author to
    have added one.
    """

    __abstract__ = True


def tenant_table_names() -> frozenset[str]:
    """Every mapped table that carries an ``org_id``, derived from the mappers.

    Derived rather than hand-listed so a new tenant model cannot be added
    without automatically picking up the guard and the RLS migration.
    """
    names: set[str] = set()
    for mapper in Base.registry.mappers:
        table = mapper.local_table
        if table is None or ORG_ID_COLUMN not in table.c:
            continue
        if not issubclass(mapper.class_, TenantMixin):
            continue
        name = getattr(table, "name", None)
        if isinstance(name, str):
            names.add(name)
    return frozenset(names)
