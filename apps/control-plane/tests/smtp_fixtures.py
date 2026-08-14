"""Fakes for the SMTP sender.

Two of them, for two different jobs.

``RecordingTransport`` opens no socket at all: it is how the sender's own
behaviour — threading, shedding, failure handling, what reaches the log — is
tested without anything resembling a network.

``FakeRelay`` is a real SMTP server on loopback, so the ``smtplib`` code path,
the AUTH exchange and the wire format of the rendered message are exercised
against something that actually speaks the protocol. **Nothing here reaches
outside 127.0.0.1**, which matters for the same reason enrichment has no HTTP
client: a suite that can reach a real relay by accident is a suite that mails a
real person by accident.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from email import message_from_bytes
from email.message import EmailMessage, Message
from typing import Any

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

from threatsculpt.auth.smtp_config import SmtpConfig
from threatsculpt.config import Settings

#: Never used against a real database — these settings exist to be validated,
#: not connected to. Tests that need a database take the ``settings`` fixture.
DUMMY_DATABASE_URL = "postgresql://nobody@127.0.0.1:1/unused"
DUMMY_JWT_SECRET = "unit-test-jwt-secret-long-enough-to-pass-validation"

RELAY_USERNAME = "relay-user"
RELAY_PASSWORD = "relay-password"

#: How long a test waits for a fire-and-forget send to land.
DELIVERY_TIMEOUT_SECONDS = 5.0


def base_settings(**overrides: Any) -> Settings:
    """A minimal valid ``Settings``, with no email delivery configured."""
    values: dict[str, Any] = {
        "environment": "test",
        "database_url": DUMMY_DATABASE_URL,
        "jwt_secret": DUMMY_JWT_SECRET,
        "cookie_secure": False,
        "log_json": False,
    }
    return Settings(**{**values, **overrides})


def smtp_settings(**overrides: Any) -> Settings:
    """A coherent SMTP configuration pointing at a loopback relay.

    ``smtp_verify_on_start`` is off by default so that constructing a sender in
    a unit test does not try to reach anything; the tests that are *about* the
    preflight turn it back on.
    """
    values: dict[str, Any] = {
        "email_delivery": "smtp",
        "smtp_host": "127.0.0.1",
        "smtp_port": 2525,
        "smtp_tls": "none",
        "smtp_from_email": "no-reply@threatsculpt.example",
        "public_base_url": "http://localhost:5173",
        "smtp_verify_on_start": False,
    }
    return base_settings(**{**values, **overrides})


def loopback_config(**overrides: Any) -> SmtpConfig:
    """A ready-made ``SmtpConfig`` for tests that skip the settings layer."""
    values: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": 2525,
        "tls": "none",
        "username": None,
        "password": None,
        "timeout_seconds": 2.0,
        "from_address": "no-reply@threatsculpt.example",
        "from_name": "ThreatSculpt",
        "base_url": "http://localhost:5173",
        "verify_on_start": False,
    }
    return SmtpConfig(**{**values, **overrides})


@dataclass(frozen=True, slots=True)
class RecordedSend:
    """One call that reached the transport, and the thread it arrived on."""

    message: EmailMessage
    thread_ident: int


class RecordingTransport:
    """An ``SmtpTransport`` that records instead of connecting.

    ``deliver_error`` and ``probe_error`` are the failure injection points;
    ``delay_seconds`` makes a send slow enough to prove the caller did not wait
    for it, and ``gate`` holds sends open indefinitely so the in-flight limit can
    be filled without depending on timing.
    """

    def __init__(
        self,
        *,
        deliver_error: BaseException | None = None,
        probe_error: BaseException | None = None,
        delay_seconds: float = 0.0,
        gate: threading.Event | None = None,
    ) -> None:
        self._deliver_error = deliver_error
        self._probe_error = probe_error
        self._delay_seconds = delay_seconds
        self._gate = gate
        self._lock = threading.Lock()
        self._sends: list[RecordedSend] = []
        self._entered = 0
        self.probe_calls = 0

    @property
    def entered(self) -> int:
        """Sends that have reached the transport, including any still blocked."""
        with self._lock:
            return self._entered

    @property
    def sends(self) -> tuple[RecordedSend, ...]:
        with self._lock:
            return tuple(self._sends)

    def deliver(self, config: SmtpConfig, message: EmailMessage) -> None:
        with self._lock:
            self._entered += 1
        if self._delay_seconds:
            time.sleep(self._delay_seconds)
        if self._gate is not None:
            self._gate.wait(timeout=DELIVERY_TIMEOUT_SECONDS)
        with self._lock:
            self._sends = [*self._sends, RecordedSend(message, threading.get_ident())]
        if self._deliver_error is not None:
            raise self._deliver_error

    def probe(self, config: SmtpConfig) -> None:
        self.probe_calls += 1
        if self._probe_error is not None:
            raise self._probe_error

    def wait_for(self, count: int, timeout: float = DELIVERY_TIMEOUT_SECONDS) -> bool:
        """Poll until ``count`` sends have been attempted, or give up."""
        return _wait_until(lambda: len(self.sends) >= count, timeout)


class _CollectingHandler:
    """aiosmtpd handler that keeps every accepted message."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._received: list[Message] = []

    @property
    def received(self) -> tuple[Message, ...]:
        with self._lock:
            return tuple(self._received)

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:  # noqa: N802
        parsed = message_from_bytes(envelope.content)
        with self._lock:
            self._received = [*self._received, parsed]
        return "250 Message accepted for delivery"


class FakeRelay:
    """A real SMTP server on 127.0.0.1, with optional AUTH."""

    def __init__(self, port: int, handler: _CollectingHandler) -> None:
        self.port = port
        self._handler = handler

    @property
    def received(self) -> tuple[Message, ...]:
        return self._handler.received

    def wait_for(self, count: int, timeout: float = DELIVERY_TIMEOUT_SECONDS) -> bool:
        return _wait_until(lambda: len(self.received) >= count, timeout)

    def only_message(self) -> Message:
        messages = self.received
        assert len(messages) == 1, f"expected exactly one message, got {len(messages)}"
        return messages[0]


@contextmanager
def running_relay(*, require_auth: bool = False) -> Iterator[FakeRelay]:
    """Start a loopback SMTP server for the duration of the block."""
    handler = _CollectingHandler()
    port = _free_port()
    # ``require_auth`` makes aiosmtpd warn that AUTH without TLS is a bad idea,
    # and it is right — but this relay listens on loopback, lives for one test,
    # and its credential is three lines up. The production path refuses exactly
    # that combination; see the loopback rule in ``auth.smtp_config``. Callers
    # silence the warning with ``@pytest.mark.filterwarnings``, which applies in
    # the server thread where it is actually raised.
    controller = Controller(
        handler,
        hostname="127.0.0.1",
        port=port,
        authenticator=_authenticator if require_auth else None,
        auth_require_tls=False,
        auth_required=require_auth,
    )
    controller.start()
    try:
        yield FakeRelay(port, handler)
    finally:
        controller.stop()


def _authenticator(server: Any, session: Any, envelope: Any, mechanism: str, data: Any) -> Any:
    """Accept exactly one credential pair, reject everything else."""
    if not isinstance(data, LoginPassword):
        return AuthResult(success=False, handled=False)
    expected = (RELAY_USERNAME.encode(), RELAY_PASSWORD.encode())
    if (data.login, data.password) == expected:
        return AuthResult(success=True)
    return AuthResult(success=False, handled=False)


def _free_port() -> int:
    """A port nothing is listening on, bound and released to find out."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_until(predicate: Any, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def body_of(message: Message, subtype: str) -> str:
    """The decoded ``text/<subtype>`` part of a multipart message."""
    for part in message.walk():
        if part.get_content_type() == f"text/{subtype}":
            payload = part.get_payload(decode=True)
            assert isinstance(payload, bytes)
            return payload.decode("utf-8")
    raise AssertionError(f"no text/{subtype} part in the message")
