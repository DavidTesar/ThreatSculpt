"""Invariants every mapped model must hold.

These are cheap structural checks over the mapper registry rather than
behavioural tests. They exist because the properties below are easy to break
silently when adding a model, and the resulting failure shows up far from the
cause — as a 500 on an unrelated route, or as a table with no tenant isolation.
"""

from __future__ import annotations

import pytest

from threatsculpt.db.base import ORG_ID_COLUMN, Base, TenantMixin, TenantModel
from threatsculpt.models import Org, Vulnerability


def _mapped_classes() -> list[type]:
    return [mapper.class_ for mapper in Base.registry.mappers]


def test_every_mapper_fetches_server_defaults_eagerly() -> None:
    """``eager_defaults`` must stay on for every model.

    ``Base.__mapper_args__`` sets it, but a model that declares its own
    ``__mapper_args__`` — for a polymorphic identity, say — silently replaces the
    inherited dict and loses it. The symptom is remote from the cause: every
    successful UPDATE of that model 500s, because ``updated_at`` is left expired
    and the lazy refresh is an unscoped ORM SELECT the tenancy guard refuses.

    Asserted over the registry so it holds for models any workstream adds.

    The comparison is ``is not True`` deliberately. ``eager_defaults`` is
    tri-state — ``True``, ``False``, or the default ``"auto"`` — and ``"auto"``
    is a *truthy string* that uses RETURNING for INSERT but **not** for UPDATE.
    A truthiness check here passes on ``"auto"`` and misses exactly the case
    this test is for.
    """
    without = [
        mapper.class_.__name__
        for mapper in Base.registry.mappers
        if mapper.eager_defaults is not True
    ]

    assert without == [], (
        f"models without eager_defaults=True: {without}. A model declaring its "
        "own __mapper_args__ must include {'eager_defaults': True}."
    )


def test_every_model_carrying_org_id_subclasses_tenant_model() -> None:
    """``org_id`` alone is not tenancy — the base class is what enrols a table.

    A model that adds an ``org_id`` column by hand without subclassing
    ``TenantModel`` would be reachable outside ``ScopedRepository`` and would be
    missing from the RLS migration: a table full of customer data with no
    isolation at any of the three layers.
    """
    stragglers = [
        mapper.class_.__name__
        for mapper in Base.registry.mappers
        if mapper.local_table is not None
        and ORG_ID_COLUMN in mapper.local_table.c
        and not issubclass(mapper.class_, TenantMixin)
    ]

    assert stragglers == []


@pytest.mark.parametrize("model", [Org, Vulnerability])
def test_global_tables_are_not_tenant_scoped(model: type) -> None:
    """``orgs`` is the tenant; ``vulnerabilities`` is shared CVE reference data.

    Both are deliberately outside the guard. If either ever gained an ``org_id``
    it would need to move under ``TenantModel``, and this failing is the signal.
    """
    assert not issubclass(model, TenantModel)
    assert ORG_ID_COLUMN not in model.__table__.c  # type: ignore[attr-defined]


def test_every_tenant_model_has_timestamps_and_a_uuid_primary_key() -> None:
    """Shape assumed by the repository, pagination ordering, and audit rows."""
    missing: list[str] = []
    for mapper in Base.registry.mappers:
        if not issubclass(mapper.class_, TenantModel) or mapper.local_table is None:
            continue
        columns = mapper.local_table.c
        for required in ("id", "created_at", "updated_at", ORG_ID_COLUMN):
            if required not in columns:
                missing.append(f"{mapper.class_.__name__}.{required}")

    assert missing == []
