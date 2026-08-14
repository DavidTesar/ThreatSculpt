"""The whole point: this service can now onboard somebody.

Registration, a real message over a real SMTP session, the link out of that
message, verification, and a login that would have been refused a moment
earlier. Against a relay on 127.0.0.1 — a fake in the sense that it is not a
mail provider, not in the sense that the protocol is skipped.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from email.message import Message
from urllib.parse import parse_qs, urlsplit

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from tests.smtp_fixtures import (
    RELAY_PASSWORD,
    RELAY_USERNAME,
    FakeRelay,
    body_of,
    running_relay,
)
from threatsculpt.app import create_app
from threatsculpt.auth.smtp import SmtpEmailSender
from threatsculpt.auth.smtp_config import SmtpConfigurationError
from threatsculpt.config import Settings
from threatsculpt.db.engine import build_engine, build_session_factory

API = "/api/v1"
PASSWORD = "correct-horse-battery-staple"
PUBLIC_ORIGIN = "http://localhost:5173"

_LINK_PATTERN = re.compile(r"https?://\S+/verify-email\?token=\S+")


def smtp_app_settings(settings: Settings, relay: FakeRelay, **overrides: object) -> Settings:
    """The suite's database settings, wired to the loopback relay.

    ``allow_undeliverable_email`` is off and ``smtp_verify_on_start`` is on, so
    this app only starts if the boot guard is satisfied and the relay accepted
    the configuration — both of which are part of what is being proved.
    """
    return settings.model_copy(
        update={
            "email_delivery": "smtp",
            "allow_undeliverable_email": False,
            "smtp_host": "127.0.0.1",
            "smtp_port": relay.port,
            "smtp_tls": "none",
            "smtp_from_email": "no-reply@threatsculpt.example",
            "smtp_from_name": "ThreatSculpt",
            "smtp_verify_on_start": True,
            "smtp_timeout_seconds": 5.0,
            "public_base_url": PUBLIC_ORIGIN,
            **overrides,
        }
    )


@pytest_asyncio.fixture
async def relay() -> AsyncIterator[FakeRelay]:
    with running_relay() as running:
        yield running


@pytest_asyncio.fixture
async def smtp_client(settings: Settings, relay: FakeRelay) -> AsyncIterator[AsyncClient]:
    """An app that delivers over SMTP, wired the way ``conftest`` wires the rest."""
    app = create_app(smtp_app_settings(settings, relay))
    engine = build_engine(settings)
    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as http:
            yield http
    finally:
        app.state.email_sender.close()
        await engine.dispose()


async def register(client: AsyncClient, *, slug: str, email: str) -> None:
    response = await client.post(
        f"{API}/auth/register",
        json={
            "org_name": slug.replace("-", " ").title(),
            "org_slug": slug,
            "email": email,
            "password": PASSWORD,
            "full_name": "Test Owner",
        },
    )
    assert response.status_code == 201, response.text


def link_from(message: Message) -> str:
    """The verification link out of the delivered plain-text part."""
    found = _LINK_PATTERN.search(body_of(message, "plain"))
    assert found is not None, "the delivered message carried no verification link"
    return found.group(0)


def token_from(link: str) -> str:
    token = parse_qs(urlsplit(link).query).get("token", [""])[0]
    assert token.startswith("tsv_"), f"unexpected token in the link: {token[:4]!r}…"
    return token


async def test_a_registered_user_receives_a_link_and_can_then_log_in(
    smtp_client: AsyncClient, relay: FakeRelay
) -> None:
    """Register, read the message off the relay, verify, log in."""
    email = "owner@onboarding.example"
    await register(smtp_client, slug="onboarding-co", email=email)

    assert relay.wait_for(1), "no message reached the relay"
    message = relay.only_message()
    assert message["To"] == email
    assert "no-reply@threatsculpt.example" in message["From"]
    assert "onboarding-co" in message["Subject"]

    link = link_from(message)
    assert link.startswith(f"{PUBLIC_ORIGIN}/verify-email?token=")

    verified = await smtp_client.post(f"{API}/auth/verify-email", json={"token": token_from(link)})
    assert verified.status_code == 200, verified.text
    assert verified.json()["data"]["verified"] is True

    logged_in = await smtp_client.post(
        f"{API}/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert logged_in.status_code == 200, logged_in.text
    assert logged_in.json()["data"]["access_token"]


async def test_the_delivered_message_carries_both_a_text_and_an_html_part(
    smtp_client: AsyncClient, relay: FakeRelay
) -> None:
    await register(smtp_client, slug="multipart-co", email="owner@multipart.example")

    assert relay.wait_for(1)
    message = relay.only_message()
    assert message.get_content_type() == "multipart/alternative"
    link = link_from(message)
    assert link in body_of(message, "plain")
    assert link in body_of(message, "html")


async def test_login_is_refused_until_the_link_is_followed(
    smtp_client: AsyncClient, relay: FakeRelay
) -> None:
    """The message is what unlocks the account, not a side effect of sending it."""
    email = "owner@unproved.example"
    await register(smtp_client, slug="unproved-co", email=email)
    assert relay.wait_for(1)

    refused = await smtp_client.post(
        f"{API}/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert refused.status_code == 401, refused.text

    await smtp_client.post(
        f"{API}/auth/verify-email", json={"token": token_from(link_from(relay.only_message()))}
    )
    accepted = await smtp_client.post(
        f"{API}/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert accepted.status_code == 200, accepted.text


async def test_resend_delivers_a_fresh_working_link(
    smtp_client: AsyncClient, relay: FakeRelay
) -> None:
    """The documented recovery route for a message that never arrived."""
    email = "owner@resend.example"
    await register(smtp_client, slug="resend-co", email=email)
    assert relay.wait_for(1)

    session = await smtp_client.post(
        f"{API}/auth/register",
        json={
            "org_name": "Resend Two",
            "org_slug": "resend-two",
            "email": "owner@resend-two.example",
            "password": PASSWORD,
            "full_name": "Second Owner",
        },
    )
    assert session.status_code == 201
    token = session.json()["data"]["access_token"]
    assert relay.wait_for(2)

    resent = await smtp_client.post(
        f"{API}/auth/verify-email/resend", headers={"Authorization": f"Bearer {token}"}
    )
    assert resent.status_code == 200, resent.text
    assert relay.wait_for(3)

    latest = relay.received[-1]
    assert latest["To"] == "owner@resend-two.example"
    verified = await smtp_client.post(
        f"{API}/auth/verify-email", json={"token": token_from(link_from(latest))}
    )
    assert verified.status_code == 200, verified.text


@pytest.mark.filterwarnings("ignore:Requiring AUTH while not requiring TLS")
async def test_delivery_works_through_an_authenticating_relay(settings: Settings) -> None:
    """The corporate-relay case: credentials are actually presented.

    The fake relay accepts AUTH without TLS, which it warns about and which the
    production path refuses outright — see the loopback rule in
    ``auth.smtp_config``. Warning silenced here rather than globally.
    """
    with running_relay(require_auth=True) as secured:
        app = create_app(
            smtp_app_settings(
                settings,
                secured,
                smtp_username=RELAY_USERNAME,
                smtp_password=SecretStr(RELAY_PASSWORD),
            )
        )
        engine = build_engine(settings)
        app.state.engine = engine
        app.state.session_factory = build_session_factory(engine)
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://testserver"
            ) as http:
                await register(http, slug="secured-co", email="owner@secured.example")
                assert secured.wait_for(1), "the authenticated relay received nothing"
                assert secured.only_message()["To"] == "owner@secured.example"
        finally:
            app.state.email_sender.close()
            await engine.dispose()


@pytest.mark.filterwarnings("ignore:Requiring AUTH while not requiring TLS")
async def test_a_wrong_relay_password_refuses_the_boot(settings: Settings) -> None:
    """Caught at startup, not at 2am on somebody's registration."""
    with running_relay(require_auth=True) as secured, pytest.raises(SmtpConfigurationError):
        create_app(
            smtp_app_settings(
                settings,
                secured,
                smtp_username=RELAY_USERNAME,
                smtp_password=SecretStr("not-the-relay-password"),
            )
        )


async def test_the_smtp_app_holds_the_real_sender(
    smtp_client: AsyncClient,
) -> None:
    sender = smtp_client._transport.app.state.email_sender  # type: ignore[attr-defined]
    assert isinstance(sender, SmtpEmailSender)
