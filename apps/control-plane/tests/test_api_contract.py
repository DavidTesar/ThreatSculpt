"""The contract in docs/API.md: envelope, error model, pagination, health, audit."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.factories import (
    API,
    create_business_service,
    create_network,
    register_tenant,
)
from threatsculpt.config import Settings
from threatsculpt.core.pagination import MAX_PER_PAGE

# --- envelope and errors ---------------------------------------------------


async def test_every_success_response_is_enveloped(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")

    response = await client.get(f"{API}/networks", headers=tenant.auth_header)

    body = response.json()
    assert set(body) >= {"data", "error"}
    assert body["error"] is None


async def test_paginated_collections_carry_meta(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)

    body = (await client.get(f"{API}/networks", headers=tenant.auth_header)).json()

    assert body["meta"] == {"page": 1, "per_page": 50, "total": 1}


async def test_errors_carry_a_stable_code_and_no_stack_trace(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")

    response = await client.get(
        f"{API}/networks/00000000-0000-0000-0000-000000000000", headers=tenant.auth_header
    )

    body = response.json()
    assert body["data"] is None
    assert body["error"]["code"] == "not_found"
    assert "Traceback" not in response.text
    assert "sqlalchemy" not in response.text.lower()


async def test_invalid_uuid_in_the_path_is_a_400_not_a_500(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")

    response = await client.get(f"{API}/networks/not-a-uuid", headers=tenant.auth_header)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "validation_error"


async def test_invalid_cidr_is_rejected_at_the_boundary(client: AsyncClient) -> None:
    """A network address never reaches the database as an unvalidated string."""
    tenant = await register_tenant(client, "acme")

    response = await client.post(
        f"{API}/networks",
        json={"name": "bad", "cidr": "10.0.0.0/8; DROP TABLE networks"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 400
    assert response.json()["error"]["field"] == "cidr"


async def test_a_404_route_is_still_enveloped(client: AsyncClient) -> None:
    response = await client.get(f"{API}/no-such-resource")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


async def test_response_carries_a_request_id_header(client: AsyncClient) -> None:
    response = await client.get("/health")

    assert response.headers["X-Request-ID"]


async def test_an_inbound_request_id_is_echoed_but_sanitised(client: AsyncClient) -> None:
    response = await client.get("/health", headers={"X-Request-ID": "abc-123\ninjected"})

    assert "\n" not in response.headers["X-Request-ID"]


# --- pagination bounds -----------------------------------------------------


async def test_per_page_above_the_maximum_is_rejected(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")

    response = await client.get(
        f"{API}/networks?per_page={MAX_PER_PAGE + 1}", headers=tenant.auth_header
    )

    assert response.status_code == 400


async def test_pagination_returns_the_requested_slice(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    for index in range(5):
        await create_network(client, tenant, name=f"net-{index}", cidr=f"10.{index}.0.0/16")

    page_two = await client.get(f"{API}/networks?page=2&per_page=2", headers=tenant.auth_header)

    body = page_two.json()
    assert len(body["data"]) == 2
    assert body["meta"] == {"page": 2, "per_page": 2, "total": 5}


# --- health ---------------------------------------------------------------


async def test_health_is_unauthenticated_and_terse(client: AsyncClient) -> None:
    response = await client.get("/health")

    assert response.status_code == 200
    assert response.json()["data"] == {"status": "ok", "environment": "test"}


async def test_readiness_reports_the_database(client: AsyncClient) -> None:
    response = await client.get("/ready")

    assert response.status_code == 200
    assert response.json()["data"] == {"status": "ok", "database": "ok"}


# --- CORS -----------------------------------------------------------------


async def test_cors_reflects_only_configured_origins(client: AsyncClient) -> None:
    allowed = await client.get("/health", headers={"Origin": "http://testserver"})
    denied = await client.get("/health", headers={"Origin": "http://evil.example"})

    assert allowed.headers.get("access-control-allow-origin") == "http://testserver"
    assert "access-control-allow-origin" not in denied.headers


async def test_openapi_is_served_outside_production(client: AsyncClient) -> None:
    assert (await client.get("/openapi.json")).status_code == 200


async def test_openapi_is_not_served_in_production(settings: Settings) -> None:
    from threatsculpt.app import create_app

    production = create_app(settings.model_copy(update={"environment": "production"}))
    transport = ASGITransport(app=production)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        assert (await http.get("/openapi.json")).status_code == 404
        assert (await http.get("/docs")).status_code == 404


# --- audit log ------------------------------------------------------------


async def test_writes_are_audited(client: AsyncClient, app_engine: AsyncEngine) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        actions = [
            row[0]
            for row in (
                await connection.execute(text("SELECT action FROM audit_log ORDER BY created_at"))
            ).all()
        ]

    assert "auth.register" in actions
    assert "network.created" in actions


async def test_failed_logins_are_audited(client: AsyncClient, app_engine: AsyncEngine) -> None:
    tenant = await register_tenant(client, "acme")
    await client.post(
        f"{API}/auth/login", json={"email": tenant.email, "password": "wrong-password-here"}
    )

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        count = (
            await connection.execute(
                text("SELECT count(*) FROM audit_log WHERE action = 'auth.login_failed'")
            )
        ).scalar_one()

    assert count == 1


async def test_audit_metadata_never_stores_a_password(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    tenant = await register_tenant(client, "acme")

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        blob = (
            await connection.execute(text("SELECT string_agg(metadata::text, ' ') FROM audit_log"))
        ).scalar_one()

    assert tenant.password not in (blob or "")


async def test_audit_log_is_append_only_for_the_application_role(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """The app holds INSERT and SELECT; UPDATE and DELETE are not granted."""
    from sqlalchemy.exc import DBAPIError

    tenant = await register_tenant(client, "acme")

    async with app_engine.connect() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        with pytest.raises(DBAPIError, match="permission denied"):
            await connection.execute(text("UPDATE audit_log SET action = 'tampered'"))

    async with app_engine.connect() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        with pytest.raises(DBAPIError, match="permission denied"):
            await connection.execute(text("DELETE FROM audit_log"))


# --- successful writes -----------------------------------------------------


async def test_successful_patch_returns_the_updated_row(client: AsyncClient) -> None:
    """Regression: a successful update used to 500.

    ``TimestampMixin.updated_at`` carries ``onupdate=func.now()``, a SQL-side
    default, so SQLAlchemy expires the attribute after flush. Serialising the
    response then triggered a lazy refresh — an ORM SELECT with no scoped
    execution option — which the tenancy guard correctly refused. Every PATCH
    route in the service sits on this path.
    """
    tenant = await register_tenant(client, "acme")
    network_id = await create_network(client, tenant, name="HQ")

    response = await client.patch(
        f"{API}/networks/{network_id}",
        json={"name": "HQ renamed", "authorized": False},
        headers=tenant.auth_header,
    )

    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["name"] == "HQ renamed"
    assert data["authorized"] is False
    assert data["updated_at"] is not None


async def test_successful_patch_persists(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    network_id = await create_network(client, tenant, name="HQ")

    await client.patch(
        f"{API}/networks/{network_id}",
        json={"name": "HQ renamed"},
        headers=tenant.auth_header,
    )
    refetched = await client.get(f"{API}/networks/{network_id}", headers=tenant.auth_header)

    assert refetched.json()["data"]["name"] == "HQ renamed"


async def test_successful_patch_advances_updated_at(client: AsyncClient) -> None:
    """The column exists to record when the row changed; prove it does."""
    tenant = await register_tenant(client, "acme")
    network_id = await create_network(client, tenant, name="HQ")
    before = (await client.get(f"{API}/networks/{network_id}", headers=tenant.auth_header)).json()[
        "data"
    ]["updated_at"]

    patched = await client.patch(
        f"{API}/networks/{network_id}",
        json={"name": "HQ renamed"},
        headers=tenant.auth_header,
    )

    assert patched.json()["data"]["updated_at"] >= before


async def test_successful_patch_on_business_services(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    service_id = await create_business_service(client, tenant)

    response = await client.patch(
        f"{API}/business-services/{service_id}",
        json={"criticality": "low", "revenue_at_risk": "125000.00"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 200, response.text
    assert response.json()["data"]["criticality"] == "low"
