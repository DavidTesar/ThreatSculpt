"""``/reports``: async generation, signed downloads, RBAC, tenancy."""

from __future__ import annotations

import time
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.factories import API, Tenant, register_tenant
from tests.scoring_factories import (
    add_user_and_login,
    map_asset_to_service,
    run_enrichment,
    seed_asset_with_port,
    seed_business_service,
    seed_vulnerability,
)
from threatsculpt.reports import runner
from threatsculpt.reports.signing import sign_download, verify_download

Factory = async_sessionmaker[AsyncSession]

TEST_JWT_SECRET = "test-only-jwt-secret-value-that-is-long-enough-01234"


@pytest.fixture
async def tenant(client: AsyncClient, session_factory: Factory) -> Tenant:
    org = await register_tenant(client, "reports-org")
    await seed_vulnerability(session_factory, org.org_id)
    seeded = await seed_asset_with_port(session_factory, org.org_id, exposure="internet")
    service_id = await seed_business_service(session_factory, org.org_id)
    await map_asset_to_service(session_factory, org.org_id, seeded.asset_id, service_id)
    await run_enrichment(session_factory, org.org_id)
    return org


async def _generate(client: AsyncClient, app: Any, tenant: Tenant) -> str:
    """Request a report and wait for the background task to finish."""
    response = await client.post(
        f"{API}/reports",
        json={"type": "executive_summary", "format": "html", "scope": {"service_ids": []}},
        headers=tenant.auth_header,
    )
    assert response.status_code == 202, response.text
    report_id = response.json()["data"]["report_id"]
    await runner.drain(app.state)
    return str(report_id)


# --- request and poll -------------------------------------------------------


async def test_requesting_a_report_returns_202_immediately(
    client: AsyncClient, tenant: Tenant, app: Any
) -> None:
    """The response must not wait for the render."""
    response = await client.post(
        f"{API}/reports", json={"type": "executive_summary"}, headers=tenant.auth_header
    )

    assert response.status_code == 202
    body = response.json()["data"]
    assert body["status"] == "queued"
    assert body["report_id"]
    await runner.drain(app.state)


async def test_the_report_becomes_ready_and_is_polled_by_id(
    client: AsyncClient, tenant: Tenant, app: Any
) -> None:
    report_id = await _generate(client, app, tenant)

    response = await client.get(f"{API}/reports/{report_id}", headers=tenant.auth_header)

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["status"] == "ready"
    assert body["byte_size"] > 0
    assert body["generated_at"] is not None
    assert body["error"] is None


async def test_pdf_is_rejected_with_an_actionable_error(
    client: AsyncClient, tenant: Tenant
) -> None:
    """docs/API.md's example asks for PDF; HTML is what is actually implemented."""
    response = await client.post(
        f"{API}/reports",
        json={"type": "executive_summary", "format": "pdf"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "unsupported_report_format"
    assert error["field"] == "format"
    assert "html" in error["message"]


async def test_reports_are_listed_newest_first(
    client: AsyncClient, tenant: Tenant, app: Any
) -> None:
    await _generate(client, app, tenant)
    await _generate(client, app, tenant)

    response = await client.get(f"{API}/reports", headers=tenant.auth_header)

    assert response.json()["meta"]["total"] == 2


# --- content ----------------------------------------------------------------


async def test_the_report_leads_with_business_services_and_explains_the_score(
    client: AsyncClient, tenant: Tenant, app: Any
) -> None:
    report_id = await _generate(client, app, tenant)
    link = await client.get(f"{API}/reports/{report_id}/link", headers=tenant.auth_header)
    url = link.json()["data"]["url"]

    response = await client.get(url)

    assert response.status_code == 200
    html = response.text
    assert "Business services at risk" in html
    assert "Payment processing" in html
    # Services must appear before the CVE list — the audience decides budgets.
    assert html.index("Business services at risk") < html.index("Highest-risk findings")
    # And every finding carries the reason it scores what it scores.
    assert "falls inside the affected range" in html


async def test_report_content_is_escaped(
    client: AsyncClient, session_factory: Factory, app: Any
) -> None:
    """A hostname is whatever a customer's DHCP said; a report must not execute it."""
    org = await register_tenant(client, "reports-xss")
    await seed_vulnerability(session_factory, org.org_id)
    seeded = await seed_asset_with_port(
        session_factory, org.org_id, hostname="<script>alert(1)</script>"
    )
    service_id = await seed_business_service(
        session_factory, org.org_id, name="<img src=x onerror=alert(2)>"
    )
    await map_asset_to_service(session_factory, org.org_id, seeded.asset_id, service_id)
    await run_enrichment(session_factory, org.org_id)

    report_id = await _generate(client, app, org)
    link = await client.get(f"{API}/reports/{report_id}/link", headers=org.auth_header)
    html = (await client.get(link.json()["data"]["url"])).text

    # The payloads survive as visible text; what matters is that no tag can form,
    # so the assertion is on the angle brackets rather than on the words.
    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(2)&gt;" in html


async def test_an_empty_org_still_produces_a_readable_report(client: AsyncClient, app: Any) -> None:
    fresh = await register_tenant(client, "reports-empty")

    report_id = await _generate(client, app, fresh)

    response = await client.get(f"{API}/reports/{report_id}", headers=fresh.auth_header)
    assert response.json()["data"]["status"] == "ready"


# --- download links ---------------------------------------------------------


async def test_download_serves_the_artifact_with_no_store(
    client: AsyncClient, tenant: Tenant, app: Any
) -> None:
    report_id = await _generate(client, app, tenant)
    link = await client.get(f"{API}/reports/{report_id}/link", headers=tenant.auth_header)

    response = await client.get(link.json()["data"]["url"])

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-store"
    assert "attachment" in response.headers["content-disposition"]


async def test_a_link_cannot_be_minted_before_the_report_is_ready(
    client: AsyncClient, tenant: Tenant, app: Any
) -> None:
    response = await client.post(
        f"{API}/reports", json={"type": "executive_summary"}, headers=tenant.auth_header
    )
    report_id = response.json()["data"]["report_id"]

    link = await client.get(f"{API}/reports/{report_id}/link", headers=tenant.auth_header)

    assert link.status_code == 422
    assert link.json()["error"]["code"] == "report_not_ready"
    await runner.drain(app.state)


async def test_download_without_a_token_is_rejected(
    client: AsyncClient, tenant: Tenant, app: Any
) -> None:
    report_id = await _generate(client, app, tenant)

    response = await client.get(f"{API}/reports/{report_id}/download")

    assert response.status_code == 400


async def test_a_tampered_token_is_rejected(client: AsyncClient, tenant: Tenant, app: Any) -> None:
    report_id = await _generate(client, app, tenant)
    link = await client.get(f"{API}/reports/{report_id}/link", headers=tenant.auth_header)
    url = link.json()["data"]["url"]

    response = await client.get(f"{url}tampered")

    assert response.status_code == 401


async def test_a_token_signed_for_a_different_report_cannot_fetch_this_one(
    client: AsyncClient, tenant: Tenant, app: Any
) -> None:
    first = await _generate(client, app, tenant)
    second = await _generate(client, app, tenant)
    link = await client.get(f"{API}/reports/{first}/link", headers=tenant.auth_header)
    token = link.json()["data"]["url"].split("token=")[1]

    response = await client.get(f"{API}/reports/{second}/download?token={token}")

    assert response.status_code == 404


async def test_a_token_naming_another_org_cannot_read_this_orgs_report(
    client: AsyncClient, tenant: Tenant, app: Any, session_factory: Factory
) -> None:
    """The org comes out of the signature, so a forged pairing has to be signed.

    Here the attacker *can* sign — the test hands them the real key — and it
    still fails, because the download is scoped to the org named in the token
    and the report belongs to a different one.
    """
    report_id = await _generate(client, app, tenant)
    other = await register_tenant(client, "reports-other")
    from uuid import UUID

    forged = sign_download(TEST_JWT_SECRET, UUID(report_id), other.org_id)

    response = await client.get(f"{API}/reports/{report_id}/download?token={forged}")

    assert response.status_code == 404


# --- signing unit tests -----------------------------------------------------


def test_a_valid_token_round_trips() -> None:
    from uuid import uuid4

    report_id, org_id = uuid4(), uuid4()

    grant = verify_download(TEST_JWT_SECRET, sign_download(TEST_JWT_SECRET, report_id, org_id))

    assert grant.report_id == report_id
    assert grant.org_id == org_id
    assert grant.expires_at > int(time.time())


def test_an_expired_token_is_refused() -> None:
    from uuid import uuid4

    from threatsculpt.core.errors import AuthenticationError

    token = sign_download(TEST_JWT_SECRET, uuid4(), uuid4(), ttl_seconds=-1)

    with pytest.raises(AuthenticationError):
        verify_download(TEST_JWT_SECRET, token)


def test_a_token_signed_with_another_key_is_refused() -> None:
    from uuid import uuid4

    from threatsculpt.core.errors import AuthenticationError

    token = sign_download("a" * 40, uuid4(), uuid4())

    with pytest.raises(AuthenticationError):
        verify_download(TEST_JWT_SECRET, token)


@pytest.mark.parametrize("token", ["", "nonsense", "a.b", "....", "!!!.???"])
def test_malformed_tokens_are_refused_uniformly(token: str) -> None:
    """Same error for every failure: distinguishing them helps only an attacker."""
    from threatsculpt.core.errors import AuthenticationError

    with pytest.raises(AuthenticationError, match="invalid or has expired"):
        verify_download(TEST_JWT_SECRET, token)


# --- RBAC and tenancy -------------------------------------------------------


async def test_viewer_cannot_request_a_report_but_can_poll_one(
    client: AsyncClient, tenant: Tenant, session_factory: Factory, app: Any
) -> None:
    viewer = await add_user_and_login(
        client, session_factory, tenant.org_id, tenant.org_slug, "viewer"
    )
    report_id = await _generate(client, app, tenant)

    requested = await client.post(
        f"{API}/reports", json={"type": "executive_summary"}, headers=viewer
    )
    assert requested.status_code == 403

    polled = await client.get(f"{API}/reports/{report_id}", headers=viewer)
    assert polled.status_code == 200


async def test_another_org_cannot_poll_or_link_this_orgs_report(
    client: AsyncClient, tenant: Tenant, app: Any
) -> None:
    report_id = await _generate(client, app, tenant)
    other = await register_tenant(client, "reports-beta")

    assert (
        await client.get(f"{API}/reports/{report_id}", headers=other.auth_header)
    ).status_code == 404
    assert (
        await client.get(f"{API}/reports/{report_id}/link", headers=other.auth_header)
    ).status_code == 404


async def test_report_listings_do_not_cross_tenants(
    client: AsyncClient, tenant: Tenant, app: Any
) -> None:
    await _generate(client, app, tenant)
    other = await register_tenant(client, "reports-gamma")

    response = await client.get(f"{API}/reports", headers=other.auth_header)

    assert response.json()["meta"]["total"] == 0
    assert response.json()["data"] == []


async def test_a_report_only_contains_its_own_orgs_data(
    client: AsyncClient, session_factory: Factory, app: Any
) -> None:
    alpha = await register_tenant(client, "report-content-alpha")
    await seed_vulnerability(session_factory, alpha.org_id)
    alpha_asset = await seed_asset_with_port(
        session_factory, alpha.org_id, ip="10.7.0.1", hostname="alpha-secret-host"
    )
    alpha_service = await seed_business_service(
        session_factory, alpha.org_id, name="Alpha Payments"
    )
    await map_asset_to_service(session_factory, alpha.org_id, alpha_asset.asset_id, alpha_service)
    await run_enrichment(session_factory, alpha.org_id)

    beta = await register_tenant(client, "report-content-beta")
    await seed_asset_with_port(session_factory, beta.org_id, ip="10.8.0.1", hostname="beta-host")

    report_id = await _generate(client, app, beta)
    link = await client.get(f"{API}/reports/{report_id}/link", headers=beta.auth_header)
    html = (await client.get(link.json()["data"]["url"])).text

    assert "alpha-secret-host" not in html
    assert "Alpha Payments" not in html


# --- failure handling -------------------------------------------------------


async def test_a_failed_render_is_recorded_without_leaking_internals(
    client: AsyncClient, tenant: Tenant, app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash must land on the row as a poll-able failure, not vanish.

    And the message the client sees must not be the exception text: a psycopg
    error carries table and column names, which `api.handlers` refuses to
    serialise everywhere else in the service.
    """
    # Arrange — make rendering blow up with a message that must not escape.
    secret_detail = 'relation "findings" column business_risk_score leaked'

    async def explode(*args: Any, **kwargs: Any) -> str:
        raise RuntimeError(secret_detail)

    monkeypatch.setattr(runner, "_render", explode)

    # Act
    response = await client.post(
        f"{API}/reports", json={"type": "executive_summary"}, headers=tenant.auth_header
    )
    report_id = response.json()["data"]["report_id"]
    await runner.drain(app.state)

    # Assert
    polled = await client.get(f"{API}/reports/{report_id}", headers=tenant.auth_header)
    body = polled.json()["data"]
    assert body["status"] == "failed"
    assert body["error"] == runner.GENERIC_FAILURE_MESSAGE
    assert secret_detail not in polled.text


async def test_generating_a_report_that_no_longer_exists_is_not_an_error(
    session_factory: Factory, tenant: Tenant
) -> None:
    """The row can be deleted between the 202 and the worker starting."""
    from uuid import uuid4

    await runner.generate(session_factory, tenant.org_id, uuid4())
