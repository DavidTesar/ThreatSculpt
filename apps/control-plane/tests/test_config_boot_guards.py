"""The process must refuse to start on a configuration that cannot work.

Same posture as the database-role check: a setting that can never succeed is a
deploy-time failure with an actionable message, not a service that starts
cleanly and fails every request afterwards for a reason nobody connects back to
the setting.
"""

from __future__ import annotations

import logging

import pytest

from threatsculpt.app import create_app
from threatsculpt.auth.delivery import (
    ESCAPE_HATCH_ENV_VAR,
    UndeliverableEmailError,
    assert_email_delivery_is_usable,
)
from threatsculpt.config import Settings


def test_a_deployment_that_cannot_deliver_refuses_to_start(settings: Settings) -> None:
    """Verification is enforced, so no delivery means no account can ever log in."""
    undeliverable = settings.model_copy(
        update={"email_delivery": "none", "allow_undeliverable_email": False}
    )

    with pytest.raises(UndeliverableEmailError) as raised:
        create_app(undeliverable)

    message = str(raised.value)
    assert "TS_EMAIL_DELIVERY" in message, "the refusal must name the setting"
    assert ESCAPE_HATCH_ENV_VAR in message, "the refusal must name the escape hatch"
    assert "onboard" in message or "verified" in message, "and say what actually breaks"


def test_the_memory_sender_is_no_more_deliverable_than_none(settings: Settings) -> None:
    """It exists for tests. It must not read as a working delivery mechanism."""
    with pytest.raises(UndeliverableEmailError):
        create_app(settings.model_copy(update={"allow_undeliverable_email": False}))


def test_the_escape_hatch_starts_the_app(settings: Settings) -> None:
    assert create_app(settings.model_copy(update={"allow_undeliverable_email": True})) is not None


def test_the_escape_hatch_is_logged_at_critical_every_boot(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An override left on by accident has to be visible, not forgotten."""
    with caplog.at_level(logging.CRITICAL):
        assert_email_delivery_is_usable("none", allow_undeliverable=True)

    critical = [record for record in caplog.records if record.levelno == logging.CRITICAL]
    assert critical, "running without email delivery must be logged at CRITICAL"
    assert ESCAPE_HATCH_ENV_VAR in critical[0].getMessage()


def test_nothing_is_logged_at_critical_on_a_delivering_configuration(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The CRITICAL line must mean something: it must not fire on the good path."""
    monkeypatch.setattr(
        "threatsculpt.auth.delivery.DELIVERING_MODES", frozenset({"smtp"}), raising=True
    )

    with caplog.at_level(logging.INFO):
        assert_email_delivery_is_usable("smtp", allow_undeliverable=False)

    assert [record for record in caplog.records if record.levelno >= logging.CRITICAL] == []
