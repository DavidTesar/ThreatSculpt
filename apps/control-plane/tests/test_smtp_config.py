"""SMTP settings are validated at boot, not at the first send.

The failure this prevents: registration reports success, the account exists, and
the message silently never leaves because the relay password is wrong. Nobody
finds out until a customer says they never received anything — by which point
every account created since the deploy is stuck unverified and unable to log in.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from tests.smtp_fixtures import smtp_settings
from threatsculpt.app import create_app
from threatsculpt.auth.smtp_config import SmtpConfigurationError, build_smtp_config


def test_a_complete_configuration_validates() -> None:
    config = build_smtp_config(smtp_settings(smtp_username=None, smtp_password=None))
    assert config.host == "127.0.0.1"
    assert config.base_url == "http://localhost:5173"
    assert config.is_loopback


def test_a_trailing_slash_on_the_base_url_is_normalised_away() -> None:
    """Otherwise every link is built with a double slash in it."""
    config = build_smtp_config(smtp_settings(public_base_url="https://app.example.com/"))
    assert config.base_url == "https://app.example.com"


def test_a_missing_host_refuses_the_boot() -> None:
    with pytest.raises(SmtpConfigurationError) as raised:
        build_smtp_config(smtp_settings(smtp_host=None))
    assert "TS_SMTP_HOST" in str(raised.value)


def test_a_missing_public_base_url_refuses_the_boot() -> None:
    """Without it there is no link to put in the message."""
    with pytest.raises(SmtpConfigurationError) as raised:
        build_smtp_config(smtp_settings(public_base_url=None))
    assert "TS_PUBLIC_BASE_URL" in str(raised.value)


def test_a_missing_sender_address_refuses_the_boot() -> None:
    with pytest.raises(SmtpConfigurationError) as raised:
        build_smtp_config(smtp_settings(smtp_from_email=None))
    assert "TS_SMTP_FROM_EMAIL" in str(raised.value)


def test_every_problem_is_reported_at_once() -> None:
    """Three wrong settings should cost one deploy, not three."""
    with pytest.raises(SmtpConfigurationError) as raised:
        build_smtp_config(smtp_settings(smtp_host=None, smtp_from_email=None, public_base_url=None))
    message = str(raised.value)
    assert "TS_SMTP_HOST" in message
    assert "TS_SMTP_FROM_EMAIL" in message
    assert "TS_PUBLIC_BASE_URL" in message


def test_a_username_without_a_password_refuses_the_boot() -> None:
    with pytest.raises(SmtpConfigurationError) as raised:
        build_smtp_config(smtp_settings(smtp_username="relay-user"))
    assert "TS_SMTP_PASSWORD" in str(raised.value)


def test_a_password_without_a_username_refuses_the_boot() -> None:
    with pytest.raises(SmtpConfigurationError) as raised:
        build_smtp_config(smtp_settings(smtp_password=SecretStr("hunter2")))
    assert "TS_SMTP_USERNAME" in str(raised.value)


def test_unencrypted_smtp_to_a_remote_relay_is_refused() -> None:
    """The session carries the relay password and a credential-bearing link."""
    with pytest.raises(SmtpConfigurationError) as raised:
        build_smtp_config(smtp_settings(smtp_host="smtp.example.com", smtp_tls="none"))
    message = str(raised.value)
    assert "TS_SMTP_TLS" in message
    assert "loopback" in message


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1"])
def test_unencrypted_smtp_is_permitted_on_loopback(host: str) -> None:
    """Local development and the test suite, and nothing else."""
    assert build_smtp_config(smtp_settings(smtp_host=host, smtp_tls="none")).tls == "none"


@pytest.mark.parametrize("tls", ["starttls", "implicit"])
def test_a_remote_relay_is_accepted_with_tls(tls: str) -> None:
    config = build_smtp_config(
        smtp_settings(
            smtp_host="smtp.example.com",
            smtp_tls=tls,
            smtp_port=465,
            smtp_username="relay-user",
            smtp_password=SecretStr("relay-password"),
        )
    )
    assert config.tls == tls
    assert config.username == "relay-user"


def test_a_plaintext_link_is_refused_in_production() -> None:
    """The link carries a token that grants control of the account."""
    with pytest.raises(SmtpConfigurationError) as raised:
        build_smtp_config(
            smtp_settings(
                environment="production",
                smtp_host="smtp.example.com",
                smtp_tls="starttls",
                public_base_url="http://app.example.com",
            )
        )
    assert "https" in str(raised.value)


def test_an_injected_sender_address_refuses_the_boot() -> None:
    with pytest.raises(SmtpConfigurationError):
        build_smtp_config(smtp_settings(smtp_from_email="ops@example.com\nBcc: x@example.com"))


def test_an_injected_sender_name_refuses_the_boot() -> None:
    """Otherwise it refuses every send instead, one registration at a time."""
    with pytest.raises(SmtpConfigurationError) as raised:
        build_smtp_config(smtp_settings(smtp_from_name="ThreatSculpt\r\nX-Priority: 1"))
    assert "TS_SMTP_FROM_NAME" in str(raised.value)


def test_the_relay_password_is_never_printed() -> None:
    """A dataclass repr in a traceback frame must not be a credential leak."""
    config = build_smtp_config(
        smtp_settings(smtp_username="relay-user", smtp_password=SecretStr("s3cret-relay-password"))
    )
    assert "s3cret-relay-password" not in repr(config)
    assert config.password is not None
    assert config.password.get_secret_value() == "s3cret-relay-password"


def test_an_incoherent_smtp_configuration_refuses_the_app() -> None:
    """The check runs from create_app, so it lands at deploy time."""
    with pytest.raises(SmtpConfigurationError):
        create_app(smtp_settings(smtp_host=None, allow_undeliverable_email=False))
