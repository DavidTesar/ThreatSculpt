"""How the SMTP sender behaves: off the loop, never fatal, never a token in the log.

Three properties, each with a specific failure it prevents.

*Off the loop*, because ``smtplib`` is blocking socket I/O and this is an async
service: a send that ran on the loop would stall every other in-flight request
for as long as the relay took to answer.

*Never fatal*, because by the time a message is sent the registration has
committed. Failing the request would tell the user their sign-up did not work
when it did.

*Never a token in the log*, because the token grants control of the account and
the verification link contains it.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
import threading
import time

import pytest

from tests.smtp_fixtures import RecordingTransport, loopback_config
from threatsculpt.auth.delivery import VerificationMessage
from threatsculpt.auth.smtp import MAX_IN_FLIGHT, SmtpEmailSender, preflight
from threatsculpt.auth.smtp_config import SmtpConfigurationError
from threatsculpt.observability.logging import JsonFormatter

TOKEN = "tsv_9Xk2mQpR7vT4wY8zA1bC3dE5fG6hJ0kL"

MESSAGE = VerificationMessage(email="owner@customer.example", token=TOKEN, org_slug="acme-corp")

#: Long enough that a caller which waited for it would be obvious.
SLOW_SEND_SECONDS = 0.3

#: Anything a caller that did *not* wait could plausibly take.
IMMEDIATE_SECONDS = 0.05


def _sender(transport: RecordingTransport) -> SmtpEmailSender:
    return SmtpEmailSender(loopback_config(), transport=transport)


# --- staying off the event loop ---------------------------------------------


async def test_the_blocking_send_does_not_run_on_the_event_loop() -> None:
    transport = RecordingTransport()
    sender = _sender(transport)
    loop_thread = threading.get_ident()

    sender.send_verification(MESSAGE)

    assert transport.wait_for(1), "the message never reached the transport"
    assert transport.sends[0].thread_ident != loop_thread, (
        "smtplib ran on the event loop thread, which stalls every other request"
    )
    sender.close()


async def test_the_caller_does_not_wait_for_a_slow_relay() -> None:
    transport = RecordingTransport(delay_seconds=SLOW_SEND_SECONDS)
    sender = _sender(transport)

    started = time.monotonic()
    sender.send_verification(MESSAGE)
    elapsed = time.monotonic() - started

    assert elapsed < IMMEDIATE_SECONDS, f"send_verification blocked for {elapsed:.3f}s"
    # And the loop is genuinely free while the relay is still being waited on.
    await asyncio.sleep(IMMEDIATE_SECONDS)
    assert transport.sends == (), "the slow send finished early; the timing proves nothing"
    assert transport.wait_for(1)
    sender.close()


async def test_the_event_loop_keeps_serving_while_a_send_is_in_flight() -> None:
    transport = RecordingTransport(delay_seconds=SLOW_SEND_SECONDS)
    sender = _sender(transport)
    ticks = 0

    async def tick() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    ticker = asyncio.create_task(tick())
    sender.send_verification(MESSAGE)
    await asyncio.sleep(SLOW_SEND_SECONDS / 2)
    ticker.cancel()

    assert ticks > 1, "the loop made no progress while the relay was being waited on"
    assert transport.wait_for(1)
    sender.close()


# --- failure never reaches the request --------------------------------------


def test_a_relay_failure_does_not_raise_at_the_caller() -> None:
    """Registration already committed; the account exists whatever mail does."""
    transport = RecordingTransport(deliver_error=smtplib.SMTPServerDisconnected("relay went away"))
    sender = _sender(transport)

    sender.send_verification(MESSAGE)  # must not raise

    assert transport.wait_for(1)
    sender.close()


def test_a_relay_failure_is_logged_with_the_recovery_route(
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport = RecordingTransport(deliver_error=smtplib.SMTPDataError(451, b"try later"))
    sender = _sender(transport)

    with caplog.at_level(logging.INFO):
        sender.send_verification(MESSAGE)
        assert transport.wait_for(1)
        sender.close()

    failures = [
        r for r in caplog.records if getattr(r, "event", "") == "verification_delivery_failed"
    ]
    assert failures, "a message that never left must be visible in the logs"
    assert failures[0].levelno >= logging.ERROR
    assert failures[0].org_slug == "acme-corp"  # type: ignore[attr-defined]
    assert failures[0].recipient_domain == "customer.example"  # type: ignore[attr-defined]
    assert "resend" in failures[0].getMessage()


def test_a_successful_send_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    transport = RecordingTransport()
    sender = _sender(transport)

    with caplog.at_level(logging.INFO):
        sender.send_verification(MESSAGE)
        assert transport.wait_for(1)
        sender.close()

    assert [r for r in caplog.records if getattr(r, "event", "") == "verification_delivered"]


def test_an_unsendable_message_is_refused_without_failing_the_caller(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An injected recipient is rejected by rendering, before any socket."""
    transport = RecordingTransport()
    sender = _sender(transport)
    hostile = VerificationMessage(
        email="victim@example.com\nBcc: everyone@example.com", token=TOKEN, org_slug="acme-corp"
    )

    with caplog.at_level(logging.INFO):
        sender.send_verification(hostile)  # must not raise
    sender.close()

    assert transport.sends == (), "an injected address must never reach the relay"
    rejected = [
        r for r in caplog.records if getattr(r, "event", "") == "verification_message_rejected"
    ]
    assert rejected and rejected[0].levelno >= logging.ERROR


def test_sends_are_shed_rather_than_queued_without_limit(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A dead relay must not grow a backlog until the process dies."""
    gate = threading.Event()
    transport = RecordingTransport(gate=gate)
    sender = _sender(transport)

    try:
        with caplog.at_level(logging.INFO):
            for _ in range(MAX_IN_FLIGHT):
                sender.send_verification(MESSAGE)
            sender.send_verification(MESSAGE)  # one too many

        shed = [
            r for r in caplog.records if getattr(r, "event", "") == "verification_delivery_shed"
        ]
        assert shed, "the message beyond the in-flight limit must be shed loudly"
        assert shed[0].levelno >= logging.ERROR
        assert "resend" in shed[0].getMessage()
    finally:
        gate.set()
        sender.close()


def test_shutdown_abandons_a_backlog_rather_than_waiting_it_out(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A process that will not stop is worse than a message the user can resend."""
    gate = threading.Event()
    transport = RecordingTransport(gate=gate)
    sender = _sender(transport)
    for _ in range(MAX_IN_FLIGHT):
        sender.send_verification(MESSAGE)

    gate.set()  # release only the workers already on the wire
    with caplog.at_level(logging.INFO):
        started = time.monotonic()
        sender.close()
        elapsed = time.monotonic() - started

    assert elapsed < 2.0, f"shutdown waited {elapsed:.1f}s on the backlog"
    abandoned = [
        r for r in caplog.records if getattr(r, "event", "") == "verification_delivery_abandoned"
    ]
    if abandoned:  # nothing is dropped when the pool happens to drain first
        assert abandoned[0].levelno >= logging.ERROR
        assert "resend" in abandoned[0].getMessage()


def test_a_send_after_shutdown_is_shed_rather_than_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``submit`` raises on a closed pool, and a request must never see that."""
    transport = RecordingTransport()
    sender = _sender(transport)
    sender.close()

    with caplog.at_level(logging.INFO):
        sender.send_verification(MESSAGE)  # must not raise

    assert transport.sends == ()
    shed = [r for r in caplog.records if getattr(r, "event", "") == "verification_delivery_shed"]
    assert shed and "resend" in shed[0].getMessage()


# --- the token is a credential ----------------------------------------------


@pytest.mark.parametrize(
    "transport",
    [
        RecordingTransport(),
        RecordingTransport(deliver_error=smtplib.SMTPServerDisconnected("gone")),
    ],
    ids=["delivered", "failed"],
)
def test_the_token_never_reaches_the_log(
    transport: RecordingTransport, caplog: pytest.LogCaptureFixture
) -> None:
    """Not in the message, not in an extra, not in a traceback."""
    sender = SmtpEmailSender(loopback_config(), transport=transport)

    with caplog.at_level(logging.DEBUG):
        sender.send_verification(MESSAGE)
        assert transport.wait_for(1)
        sender.close()

    for record in caplog.records:
        fields = " ".join([record.getMessage(), *(str(v) for v in record.__dict__.values())])
        assert TOKEN not in fields, f"the token leaked into {record.name}"
        assert "verify-email?token=" not in fields, "the link is a credential too"
        # And in what a deployment actually writes, tracebacks included.
        assert TOKEN not in JsonFormatter().format(record)


def test_a_token_echoed_back_by_a_relay_is_still_masked(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Defence in depth: this module does not choose what a relay puts in an error."""
    echoed = smtplib.SMTPDataError(550, f"rejected: {TOKEN}".encode())
    transport = RecordingTransport(deliver_error=echoed)
    sender = SmtpEmailSender(loopback_config(), transport=transport)

    with caplog.at_level(logging.DEBUG):
        sender.send_verification(MESSAGE)
        assert transport.wait_for(1)
        sender.close()

    for record in caplog.records:
        assert TOKEN not in JsonFormatter().format(record), (
            "observability.logging must mask a tsv_ value wherever it appears"
        )


def test_the_recipient_local_part_is_not_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Only the domain, matching what the null sender already logs."""
    transport = RecordingTransport()
    sender = _sender(transport)

    with caplog.at_level(logging.DEBUG):
        sender.send_verification(MESSAGE)
        assert transport.wait_for(1)
        sender.close()

    assert "owner@customer.example" not in caplog.text


# --- startup preflight ------------------------------------------------------


def test_a_rejected_credential_refuses_the_boot() -> None:
    """It will be rejected at send time too, and then nobody finds out."""
    transport = RecordingTransport(
        probe_error=smtplib.SMTPAuthenticationError(535, b"authentication failed")
    )

    with pytest.raises(SmtpConfigurationError) as raised:
        preflight(loopback_config(), transport)

    assert "TS_SMTP_PASSWORD" in str(raised.value)
    assert transport.probe_calls == 1


def test_an_unverifiable_certificate_refuses_the_boot() -> None:
    with pytest.raises(SmtpConfigurationError):
        preflight(loopback_config(), RecordingTransport(probe_error=ssl.SSLError("bad handshake")))


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError("no listener"),
        TimeoutError("no answer"),
        smtplib.SMTPConnectError(421, b"service unavailable"),
        smtplib.SMTPServerDisconnected("closed"),
    ],
)
def test_an_unreachable_relay_logs_critical_and_starts_anyway(
    error: BaseException, caplog: pytest.LogCaptureFixture
) -> None:
    """Refusing to boot on a relay blip would take the whole API down with it."""
    with caplog.at_level(logging.INFO):
        preflight(loopback_config(), RecordingTransport(probe_error=error))

    critical = [r for r in caplog.records if r.levelno >= logging.CRITICAL]
    assert critical, "an unreachable relay must be loud, since delivery will fail"
    assert getattr(critical[0], "event", "") == "smtp_preflight_unreachable"


def test_a_healthy_relay_logs_nothing_alarming(caplog: pytest.LogCaptureFixture) -> None:
    """The CRITICAL line must mean something: it must not fire on the good path."""
    with caplog.at_level(logging.INFO):
        preflight(loopback_config(), RecordingTransport())

    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
    assert [r for r in caplog.records if getattr(r, "event", "") == "smtp_preflight_ok"]
