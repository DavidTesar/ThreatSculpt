"""Delivering a verification message over SMTP, off the event loop.

Three properties this module exists to hold:

**It never blocks the loop.** ``smtplib`` is synchronous socket I/O and a relay
can take seconds to answer, or the full timeout to not answer. This is an async
service with one event loop per worker, so a blocking send would stall *every*
concurrent request for the duration, not just the one that triggered it. Sends
are therefore handed to a small bounded thread pool and the caller returns
immediately.

**It never fails a request.** By the time a message is sent the registration has
committed and the account exists: failing the request would tell the user their
sign-up did not work when it did, and leave them re-registering into a conflict.
A failed send is logged loudly instead, and the user recovers through
``POST /auth/verify-email/resend`` — which is why that endpoint exists.

**It never logs the token.** The token is a credential and the verification link
contains it, so neither the link nor the rendered message is ever logged. The
fields this module files on a record are the org and the recipient's *domain* —
enough to answer "is delivery to this customer working" and not enough to be a
credential leak. (A relay's own error text may name the address it refused, and
that is deliberate: an address is not a credential, it is already in the audit
log, and "which mailbox did the relay reject" is the question an operator has.)
``observability.logging`` masks ``tsv_`` values as a second line of defence; this
module does not rely on it.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from email.message import EmailMessage
from typing import TYPE_CHECKING, Protocol

from threatsculpt.auth.mail import UnsafeMessageError, build_verification_email, verification_link
from threatsculpt.auth.smtp_config import SmtpConfig, SmtpConfigurationError, build_smtp_config
from threatsculpt.config import Settings

if TYPE_CHECKING:
    # Typing only. ``delivery`` imports this module to build the sender, so
    # importing it back at runtime would close the cycle; ``from __future__
    # import annotations`` makes the annotations strings, so it never has to.
    from threatsculpt.auth.delivery import EmailSender, VerificationMessage

logger = logging.getLogger(__name__)

#: Worker threads. Small on purpose: a relay is a remote service, and the answer
#: to "mail is slow" is a queue, not more sockets.
SMTP_WORKER_THREADS = 4

#: Messages that may be waiting on those threads at once. Beyond this, sends are
#: shed with a loud log rather than queued: an unbounded backlog against a dead
#: relay grows until the process dies, which converts a delivery outage into a
#: total one. A shed message is recoverable through the resend endpoint.
MAX_IN_FLIGHT = 64

#: Failures that mean the configuration is wrong and will still be wrong on the
#: next attempt. Everything else — refused connection, timeout, dropped session
#: — means the relay is unwell right now, which is a different decision at boot.
FATAL_SMTP_ERRORS = (
    smtplib.SMTPAuthenticationError,
    smtplib.SMTPNotSupportedError,
    smtplib.SMTPHeloError,
    ssl.SSLError,
)


class SmtpTransport(Protocol):
    """The socket-level half, behind a seam so tests never open one."""

    def deliver(self, config: SmtpConfig, message: EmailMessage) -> None: ...

    def probe(self, config: SmtpConfig) -> None: ...


class SmtplibTransport:
    """The real thing: ``smtplib`` with TLS chosen by configuration."""

    def deliver(self, config: SmtpConfig, message: EmailMessage) -> None:
        with _connect(config) as client:
            client.send_message(message)

    def probe(self, config: SmtpConfig) -> None:
        """Connect, negotiate TLS, authenticate, and hang up. Sends nothing."""
        with _connect(config) as client:
            client.noop()


def _connect(config: SmtpConfig) -> smtplib.SMTP:
    """Open an authenticated session. Certificates are always verified."""
    context = ssl.create_default_context()
    if config.tls == "implicit":
        client: smtplib.SMTP = smtplib.SMTP_SSL(
            config.host, config.port, timeout=config.timeout_seconds, context=context
        )
    else:
        client = smtplib.SMTP(config.host, config.port, timeout=config.timeout_seconds)
        if config.tls == "starttls":
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()  # capabilities are re-read after the upgrade
    if config.username is not None and config.password is not None:
        client.login(config.username, config.password.get_secret_value())
    return client


class SmtpEmailSender:
    """An ``EmailSender`` that puts the message in front of a human.

    ``send_verification`` returns as soon as the message is queued; the socket
    work happens on a worker thread. That is why the method cannot report
    failure to its caller, and why it must not try to.
    """

    __slots__ = ("_cancelled", "_config", "_executor", "_lock", "_slots", "_transport")

    def __init__(self, config: SmtpConfig, *, transport: SmtpTransport | None = None) -> None:
        self._config = config
        self._transport = transport or SmtplibTransport()
        self._executor = ThreadPoolExecutor(
            max_workers=SMTP_WORKER_THREADS, thread_name_prefix="ts-smtp"
        )
        self._slots = threading.BoundedSemaphore(MAX_IN_FLIGHT)
        self._lock = threading.Lock()
        self._cancelled = 0

    def send_verification(self, message: VerificationMessage) -> None:
        """Queue the message. Never raises, never blocks, never logs the token."""
        domain = message.email.rpartition("@")[2]
        try:
            rendered = self._render(message)
        except UnsafeMessageError:
            # The address or the org slug could not be proved header-safe. Both
            # were validated upstream, so this is either corruption or an
            # injection attempt, and neither is a reason to fail the request.
            logger.exception(
                "verification message was refused before sending",
                extra={"event": "verification_message_rejected", "org_slug": message.org_slug},
            )
            return

        if not self._slots.acquire(blocking=False):
            logger.error(
                "verification message dropped: %d sends already in flight, so the "
                "relay is not keeping up. The account exists and is unverified; "
                "its owner can recover through POST /auth/verify-email/resend.",
                MAX_IN_FLIGHT,
                extra={
                    "event": "verification_delivery_shed",
                    "org_slug": message.org_slug,
                    "recipient_domain": domain,
                },
            )
            return

        try:
            future = self._executor.submit(self._deliver, rendered, message.org_slug, domain)
        except RuntimeError:
            # The pool is already shutting down, which ``submit`` reports by
            # raising. The caller is mid-request and must not see that.
            self._slots.release()
            logger.error(
                "verification message not queued: delivery is shutting down. The "
                "account exists and is unverified; its owner can recover through "
                "POST /auth/verify-email/resend.",
                extra={
                    "event": "verification_delivery_shed",
                    "org_slug": message.org_slug,
                    "recipient_domain": domain,
                },
            )
            return
        future.add_done_callback(self._release)

    def close(self) -> None:
        """Finish what is on the wire, drop what is only queued, and stop.

        Bounded by the socket timeout rather than by the backlog. Waiting out a
        queue of ``MAX_IN_FLIGHT`` against a slow relay could hold a shutdown for
        minutes, and a process that will not stop is how a rolling deploy stalls
        — a worse outcome than a dropped message, which the resend endpoint
        recovers. A healthy relay empties the queue in milliseconds, so in
        practice nothing is dropped; when something is, it is logged.
        """
        self._executor.shutdown(wait=True, cancel_futures=True)
        with self._lock:
            dropped = self._cancelled
        if dropped:
            logger.error(
                "%d verification message(s) were still queued at shutdown and were "
                "not sent. Those accounts exist and are unverified; their owners "
                "can recover through POST /auth/verify-email/resend.",
                dropped,
                extra={"event": "verification_delivery_abandoned", "dropped": dropped},
            )

    def _render(self, message: VerificationMessage) -> EmailMessage:
        return build_verification_email(
            from_address=self._config.from_address,
            from_name=self._config.from_name,
            recipient=message.email,
            org_slug=message.org_slug,
            link=verification_link(self._config.base_url, message.token),
        )

    def _deliver(self, rendered: EmailMessage, org_slug: str, domain: str) -> None:
        """Runs on a worker thread. Swallows nothing quietly."""
        context = {
            "event": "verification_delivered",
            "org_slug": org_slug,
            "recipient_domain": domain,
        }
        try:
            self._transport.deliver(self._config, rendered)
        except Exception:
            logger.exception(
                "verification message could not be delivered. The account exists "
                "and is unverified, so its owner cannot sign in until a message "
                "arrives; they can request another at POST /auth/verify-email/resend.",
                extra={**context, "event": "verification_delivery_failed"},
            )
            return
        logger.info("verification message delivered", extra=context)

    def _release(self, future: Future[None]) -> None:
        """Give the in-flight slot back, however the send ended."""
        if future.cancelled():
            with self._lock:
                self._cancelled += 1
        self._slots.release()


def build_smtp_sender(settings: Settings, *, transport: SmtpTransport | None = None) -> EmailSender:
    """Validate, optionally probe the relay, and return the sender.

    Called from ``build_email_sender`` during ``create_app``, so both failures
    below land at boot rather than at 2am on somebody's registration.
    """
    config = build_smtp_config(settings)
    resolved = transport or SmtplibTransport()
    if config.verify_on_start:
        preflight(config, resolved)
    return SmtpEmailSender(config, transport=resolved)


def preflight(config: SmtpConfig, transport: SmtpTransport) -> None:
    """Prove the relay accepts these credentials, without sending anything.

    The two failure classes are handled differently on purpose.

    A **wrong credential or an unusable TLS mode** will be just as wrong on
    every future attempt, so it is a configuration error and the process refuses
    to start — exactly like an unset host. This is the case worth catching: the
    symptom otherwise is a registration that reports success while the message
    silently never leaves, which nobody notices until a customer says they never
    got it.

    A **refused connection or a timeout** means the relay is down *right now*.
    That is logged at CRITICAL and the service starts anyway, because refusing
    to boot on it makes a relay blip take the whole API down and, worse, holds it
    down: a rolling deploy or a pod restart during the blip crash-loops until
    the relay returns. Trading "cannot onboard" for "cannot serve anything" is a
    bad trade, so the loud log is the escalation instead.
    """
    try:
        transport.probe(config)
    except FATAL_SMTP_ERRORS as exc:
        raise SmtpConfigurationError(
            f"the SMTP relay at {config.host}:{config.port} rejected this "
            f"configuration at startup: {type(exc).__name__}. It will reject it at "
            "send time too, and a verification message that never leaves is a "
            "sign-up that silently onboards nobody. Check TS_SMTP_USERNAME / "
            "TS_SMTP_PASSWORD and TS_SMTP_TLS.\n\n"
            "To start without this check — it does not make delivery work — set "
            "TS_SMTP_VERIFY_ON_START=0."
        ) from exc
    except Exception:
        logger.critical(
            "SMTP relay at %s:%d is unreachable at startup. Starting anyway: this "
            "looks like an outage rather than a misconfiguration, and refusing to "
            "boot on it would take the whole service down for a mail problem. "
            "Verification messages will fail until it recovers, and every failure "
            "is logged as verification_delivery_failed.",
            config.host,
            config.port,
            extra={"event": "smtp_preflight_unreachable", "smtp_host": config.host},
        )
        return
    logger.info(
        "SMTP relay accepted the configured credentials",
        extra={"event": "smtp_preflight_ok", "smtp_host": config.host},
    )
