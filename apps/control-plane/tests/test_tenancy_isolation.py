"""Cross-tenant isolation — the property the whole service exists to hold.

Three layers are tested separately, because each is supposed to hold on its own:

1. **Routes** — org A gets 404, never 403, for org B's ids.
2. **Repository / guard** — a query against a tenant table with no scope raises,
   and a repository built for org A cannot see org B's rows.
3. **RLS** — raw SQL under the wrong ``threatsculpt.org_id`` returns nothing,
   with every Python-side control bypassed.

Layer 3 is only meaningful because the application connects as a NOSUPERUSER,
NOBYPASSRLS role (see ``conftest.database``).
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from tests.factories import API, create_business_service, create_network, register_tenant
from threatsculpt.core.errors import TenancyViolationError
from threatsculpt.db.session import bind_scope, scoped_session
from threatsculpt.models.inventory import BusinessService, Network
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

# --- layer 1: routes -------------------------------------------------------


async def test_org_a_cannot_read_org_b_network(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    beta_network = await create_network(client, beta, name="Beta HQ", cidr="192.168.0.0/16")

    response = await client.get(f"{API}/networks/{beta_network}", headers=alpha.auth_header)

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


async def test_cross_tenant_read_is_404_not_403(client: AsyncClient) -> None:
    """403 would confirm the row exists. docs/API.md requires 404."""
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    beta_network = await create_network(client, beta)

    cross_tenant = await client.get(f"{API}/networks/{beta_network}", headers=alpha.auth_header)
    genuinely_missing = await client.get(
        f"{API}/networks/00000000-0000-0000-0000-000000000000", headers=alpha.auth_header
    )

    assert cross_tenant.status_code == genuinely_missing.status_code == 404
    assert cross_tenant.json() == genuinely_missing.json()


async def test_org_a_cannot_update_org_b_network(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    beta_network = await create_network(client, beta, name="Beta HQ")

    response = await client.patch(
        f"{API}/networks/{beta_network}",
        json={"name": "owned"},
        headers=alpha.auth_header,
    )
    assert response.status_code == 404

    unchanged = await client.get(f"{API}/networks/{beta_network}", headers=beta.auth_header)
    assert unchanged.json()["data"]["name"] == "Beta HQ"


async def test_org_a_cannot_delete_org_b_network(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    beta_network = await create_network(client, beta)

    response = await client.delete(f"{API}/networks/{beta_network}", headers=alpha.auth_header)
    assert response.status_code == 404

    survivor = await client.get(f"{API}/networks/{beta_network}", headers=beta.auth_header)
    assert survivor.status_code == 200


async def test_org_a_cannot_delete_org_b_business_service(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    beta_service = await create_business_service(client, beta)

    response = await client.delete(
        f"{API}/business-services/{beta_service}", headers=alpha.auth_header
    )
    assert response.status_code == 404

    survivor = await client.get(f"{API}/business-services/{beta_service}", headers=beta.auth_header)
    assert survivor.status_code == 200


async def test_list_endpoints_only_return_your_own_rows(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    await create_network(client, alpha, name="Alpha HQ", cidr="10.0.0.0/8")
    await create_network(client, beta, name="Beta HQ", cidr="192.168.0.0/16")
    await create_network(client, beta, name="Beta DC", cidr="172.16.0.0/12")

    listing = await client.get(f"{API}/networks", headers=alpha.auth_header)

    body = listing.json()
    assert body["meta"]["total"] == 1
    assert [item["name"] for item in body["data"]] == ["Alpha HQ"]


async def test_org_a_token_cannot_be_replayed_against_org_b_data(
    client: AsyncClient,
) -> None:
    """A valid token is valid only for the org inside it."""
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    beta_service = await create_business_service(client, beta, name="Beta payments")

    response = await client.get(
        f"{API}/business-services/{beta_service}", headers=alpha.auth_header
    )

    assert response.status_code == 404


# --- layer 2: repository and guard ----------------------------------------


async def test_repository_for_org_a_cannot_see_org_b_rows(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    beta_network = await create_network(client, beta)

    alpha_scope = OrgScope.for_system(alpha.org_id)
    async with scoped_session(session_factory, alpha_scope) as session:
        repository = ScopedRepository(session, alpha_scope, Network)
        assert await repository.get(beta_network) is None
        assert await repository.count() == 0


async def test_repository_refuses_a_scope_that_disagrees_with_the_session(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")

    alpha_scope = OrgScope.for_system(alpha.org_id)
    async with scoped_session(session_factory, alpha_scope) as session:
        with pytest.raises(TenancyViolationError):
            ScopedRepository(session, OrgScope.for_system(beta.org_id), Network)


async def test_session_cannot_be_rebound_to_a_different_org(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")

    async with scoped_session(session_factory, OrgScope.for_system(alpha.org_id)) as session:
        with pytest.raises(TenancyViolationError):
            await bind_scope(session, OrgScope.for_system(beta.org_id))


async def test_unscoped_query_against_a_tenant_table_raises(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    """The structural control: this is the shape of the v1 bug, and it will not run."""
    await register_tenant(client, "alpha")

    async with session_factory() as session:
        with pytest.raises(TenancyViolationError):
            await session.execute(select(Network))


async def test_unscoped_query_raises_even_on_a_scoped_session(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    """Binding a scope is not enough — the statement must be built by the repository."""
    alpha = await register_tenant(client, "alpha")

    async with scoped_session(session_factory, OrgScope.for_system(alpha.org_id)) as session:
        with pytest.raises(TenancyViolationError):
            await session.execute(select(BusinessService))


async def test_repository_refuses_a_caller_supplied_org_id(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")

    scope = OrgScope.for_system(alpha.org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, Network)
        with pytest.raises(TenancyViolationError):
            await repository.create(name="smuggled", cidr="10.0.0.0/8", org_id=beta.org_id)


async def test_repository_refuses_to_move_a_row_between_orgs(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    alpha_network = await create_network(client, alpha)

    scope = OrgScope.for_system(alpha.org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, Network)
        network = await repository.get_or_404(alpha_network)
        with pytest.raises(TenancyViolationError):
            await repository.update(network, {"org_id": beta.org_id})


# --- layer 3: Row-Level Security ------------------------------------------


async def test_rls_blocks_a_raw_query_with_the_wrong_org_id(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """No ORM, no repository, no guard — just the database's own answer."""
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    await create_network(client, beta, name="Beta HQ", cidr="192.168.0.0/16")

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(alpha.org_id)},
        )
        visible = (await connection.execute(text("SELECT count(*) FROM networks"))).scalar_one()
    assert visible == 0

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(beta.org_id)},
        )
        visible = (await connection.execute(text("SELECT count(*) FROM networks"))).scalar_one()
    assert visible == 1


async def test_rls_returns_nothing_when_no_org_id_is_set(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """Unscoped fails closed: zero rows, never everyone's rows."""
    beta = await register_tenant(client, "beta")
    await create_network(client, beta)

    async with app_engine.begin() as connection:
        counts = {
            table: (
                await connection.execute(text(f"SELECT count(*) FROM {table}"))  # noqa: S608
            ).scalar_one()
            for table in ("networks", "users", "audit_log", "refresh_tokens")
        }

    assert counts == {"networks": 0, "users": 0, "audit_log": 0, "refresh_tokens": 0}


async def test_rls_blocks_a_raw_update_across_orgs(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    beta_network = await create_network(client, beta, name="Beta HQ")

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(alpha.org_id)},
        )
        result = await connection.execute(
            text("UPDATE networks SET name = 'owned' WHERE id = :nid"), {"nid": beta_network}
        )
        assert result.rowcount == 0

    survivor = await client.get(f"{API}/networks/{beta_network}", headers=beta.auth_header)
    assert survivor.json()["data"]["name"] == "Beta HQ"


async def test_rls_blocks_a_raw_delete_across_orgs(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    beta_network = await create_network(client, beta)

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(alpha.org_id)},
        )
        result = await connection.execute(
            text("DELETE FROM networks WHERE id = :nid"), {"nid": beta_network}
        )
        assert result.rowcount == 0

    assert (
        await client.get(f"{API}/networks/{beta_network}", headers=beta.auth_header)
    ).status_code == 200


async def test_rls_with_check_blocks_inserting_into_another_org(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """``WITH CHECK`` stops a write *into* another org, not just reads out of it."""
    from sqlalchemy.exc import DBAPIError

    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(alpha.org_id)},
        )
        with pytest.raises(DBAPIError):
            await connection.execute(
                text(
                    "INSERT INTO networks (org_id, name, cidr) "
                    "VALUES (:org, 'smuggled', '10.9.0.0/16')"
                ),
                {"org": str(beta.org_id)},
            )


async def test_application_role_is_not_a_superuser(app_engine: AsyncEngine) -> None:
    """If this ever fails, every RLS test above is vacuous."""
    async with app_engine.connect() as connection:
        row = (
            await connection.execute(
                text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            )
        ).one()

    assert row.rolsuper is False
    assert row.rolbypassrls is False
