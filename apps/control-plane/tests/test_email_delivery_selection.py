"""Which sender each mode selects, and which modes the boot guard still refuses.

``DELIVERING_MODES`` was empty, and that emptiness was the whole mechanism: the
guard trusts the set and has no other way to tell whether a sender delivers. Now
that a name has been added to it, an edit that adds one *more* — or that adds
``none`` "so the tests stop failing" — would silently defeat the refusal and
produce a deployment that starts cleanly and onboards nobody. So the set is
asserted exactly, and every mode the settings can express is checked to be
either genuinely delivering or genuinely refused.
"""

from __future__ import annotations

from typing import get_args

import pytest

from tests.smtp_fixtures import base_settings, smtp_settings
from threatsculpt.app import create_app
from threatsculpt.auth.delivery import (
    DELIVERING_MODES,
    MemoryEmailSender,
    NullEmailSender,
    UndeliverableEmailError,
    assert_email_delivery_is_usable,
    build_email_sender,
    can_deliver,
)
from threatsculpt.auth.smtp import SmtpEmailSender
from threatsculpt.config import Settings

#: Every value ``TS_EMAIL_DELIVERY`` accepts, read off the settings model so a
#: new mode cannot be added without this file noticing.
ALL_MODES: tuple[str, ...] = get_args(Settings.model_fields["email_delivery"].annotation)

#: Written out rather than derived from ``DELIVERING_MODES``: deriving it would
#: make the assertions below true by construction, which is precisely the bug
#: this file exists to catch.
NON_DELIVERING_MODES = ("none", "memory")


def test_the_set_of_delivering_modes_is_exactly_smtp() -> None:
    assert frozenset({"smtp"}) == DELIVERING_MODES
    assert set(ALL_MODES) == set(NON_DELIVERING_MODES) | DELIVERING_MODES


@pytest.mark.parametrize("mode", NON_DELIVERING_MODES)
def test_the_guard_still_refuses_every_mode_that_cannot_deliver(mode: str) -> None:
    """The refusal has to survive the set no longer being empty."""
    assert not can_deliver(mode)
    with pytest.raises(UndeliverableEmailError) as raised:
        assert_email_delivery_is_usable(mode, allow_undeliverable=False)
    assert "TS_EMAIL_DELIVERY" in str(raised.value)


@pytest.mark.parametrize("mode", NON_DELIVERING_MODES)
def test_an_app_on_a_non_delivering_mode_still_refuses_to_start(mode: str) -> None:
    with pytest.raises(UndeliverableEmailError):
        create_app(base_settings(email_delivery=mode, allow_undeliverable_email=False))


def test_smtp_satisfies_the_guard() -> None:
    assert can_deliver("smtp")
    assert_email_delivery_is_usable("smtp", allow_undeliverable=False)


@pytest.mark.parametrize("mode", ALL_MODES)
def test_every_declared_mode_either_delivers_or_is_refused(mode: str) -> None:
    """No mode may be quietly neither: that is how a gap gets in."""
    if can_deliver(mode):
        assert_email_delivery_is_usable(mode, allow_undeliverable=False)
        return
    with pytest.raises(UndeliverableEmailError):
        assert_email_delivery_is_usable(mode, allow_undeliverable=False)


def test_none_selects_the_sender_that_delivers_nothing() -> None:
    sender = build_email_sender(base_settings(email_delivery="none"))
    assert isinstance(sender, NullEmailSender)
    sender.close()


def test_memory_selects_the_in_process_sender() -> None:
    sender = build_email_sender(base_settings(email_delivery="memory"))
    assert isinstance(sender, MemoryEmailSender)
    sender.close()


def test_an_unknown_mode_falls_back_to_delivering_nothing() -> None:
    """Fails closed. A typo must not silently select a real relay."""
    sender = build_email_sender(base_settings().model_copy(update={"email_delivery": "typo"}))
    assert isinstance(sender, NullEmailSender)
    sender.close()


def test_smtp_selects_the_smtp_sender() -> None:
    sender = build_email_sender(smtp_settings())
    assert isinstance(sender, SmtpEmailSender)
    sender.close()


def test_an_app_configured_for_smtp_starts_without_the_escape_hatch() -> None:
    """The point of the whole exercise: a deployment that can onboard somebody."""
    app = create_app(smtp_settings(allow_undeliverable_email=False))
    assert isinstance(app.state.email_sender, SmtpEmailSender)
    app.state.email_sender.close()
