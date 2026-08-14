"""Where an outbound message goes.

Delivery is a seam: the verification state machine hands a finished message to
an ``EmailSender`` and stops caring. Nothing that decides whether an address is
proved knows how — or whether — a message travels.

**One implementation here delivers mail, and two deliberately do not.**
``SmtpEmailSender`` (``auth.smtp``, selected by ``TS_EMAIL_DELIVERY=smtp``) is
the real one. ``NullEmailSender`` — still the default — records that a message
was requested and drops it, and ``MemoryEmailSender`` retains it in-process for
tests. Neither of those can onboard anybody, which is why
``assert_email_delivery_is_usable`` refuses to boot on them: an account that
never receives its message can never sign in.

SMTP rather than a vendor SDK because one relay configuration reaches SES,
SendGrid, Postmark, Mailgun and the corporate relay an enterprise customer will
insist on. Picking a vendor's SDK would be betting on which one every future
customer chooses.

The token is never logged. A verification token is a credential that grants
control of an account, so a sender that wrote it to the log stream would be a
credential in the log stream, which is precisely what ``observability.logging``
exists to prevent. The verification *link* contains the token, so it is a
credential too and is logged nowhere either.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from threatsculpt.auth.smtp import build_smtp_sender
from threatsculpt.config import Settings

logger = logging.getLogger(__name__)

#: The in-memory sender keeps a bounded buffer; a long-running development
#: process should not accumulate messages until it runs out of memory.
MAX_RETAINED_MESSAGES = 256


@dataclass(frozen=True, slots=True)
class VerificationMessage:
    """One outbound verification request. Immutable, like every other DTO here."""

    email: str
    token: str
    org_slug: str


class EmailSender(Protocol):
    """The whole contract. Implementations must not raise on delivery failure.

    A registration that rolled back because a mail provider was briefly down
    would turn somebody else's outage into a failed sign-up, and the account is
    perfectly valid without the message — it is simply unverified until one
    arrives.

    ``close`` exists because a real sender owns sockets and threads: a delivery
    mechanism that cannot be drained at shutdown loses whatever was in flight
    when the process stopped. Implementations that own nothing implement it as a
    no-op rather than leaving callers to guess whether it is there.
    """

    def send_verification(self, message: VerificationMessage) -> None: ...

    def close(self) -> None: ...


class NullEmailSender:
    """Logs that a message was wanted, delivers nothing, keeps nothing."""

    def close(self) -> None:
        """Owns nothing."""

    def send_verification(self, message: VerificationMessage) -> None:
        logger.warning(
            "email delivery is not configured; verification message was not sent",
            extra={
                "event": "email_delivery_missing",
                "org_slug": message.org_slug,
                # The address, not the token. One is a routing detail; the other
                # is a credential.
                "recipient_domain": message.email.rpartition("@")[2],
            },
        )


class MemoryEmailSender:
    """Development and tests only: retains messages in this process.

    Exists so the verification flow can be exercised end to end without mail
    infrastructure. It is a test double that happens to be shipped, not a
    delivery mechanism — nothing outside the process can ever read from it.
    """

    __slots__ = ("_messages",)

    def __init__(self) -> None:
        self._messages: list[VerificationMessage] = []

    def close(self) -> None:
        """Owns nothing."""

    def send_verification(self, message: VerificationMessage) -> None:
        retained = [*self._messages, message][-MAX_RETAINED_MESSAGES:]
        self._messages = retained

    @property
    def messages(self) -> tuple[VerificationMessage, ...]:
        return tuple(self._messages)

    def latest_token_for(self, email: str) -> str | None:
        """The most recent token issued to ``email``, or ``None``."""
        for message in reversed(self._messages):
            if message.email.lower() == email.lower():
                return message.token
        return None


#: Delivery modes that actually put a message in front of a human. **This set is
#: the whole of what ``assert_email_delivery_is_usable`` trusts**, so adding a
#: name to it is a claim that the named sender delivers — the guard has no other
#: way to tell. ``none`` and ``memory`` stay out of it because neither does, and
#: a deployment on either can onboard nobody.
DELIVERING_MODES: frozenset[str] = frozenset({"smtp"})

ESCAPE_HATCH_ENV_VAR = "TS_ALLOW_UNDELIVERABLE_EMAIL"


class UndeliverableEmailError(RuntimeError):
    """No configured way to deliver a verification message, and no opt-out."""


def can_deliver(delivery: str) -> bool:
    return delivery in DELIVERING_MODES


def build_email_sender(settings: Settings) -> EmailSender:
    """Resolve the configured sender. Unknown values fail closed, not open.

    Takes the whole ``Settings`` because a real sender needs a relay, a sender
    address and a public origin, and because building it is where those are
    validated — at boot, from ``create_app``, not on the first registration.
    """
    if settings.email_delivery == "smtp":
        return build_smtp_sender(settings)
    if settings.email_delivery == "memory":
        return MemoryEmailSender()
    return NullEmailSender()


def build_refusal_message(delivery: str) -> str:
    return (
        f"TS_EMAIL_DELIVERY={delivery!r} cannot deliver a message, so no account "
        "could ever be verified.\n\n"
        "Verification is not decoration: an unverified account cannot log in, so "
        "with this configuration the first user is locked out the moment their "
        "registration session lapses, every invited colleague is locked out "
        "immediately, and the service can onboard nobody at all.\n\n"
        "Set TS_EMAIL_DELIVERY=smtp and configure the relay: TS_SMTP_HOST, "
        "TS_SMTP_PORT, TS_SMTP_TLS, TS_SMTP_USERNAME, TS_SMTP_PASSWORD, "
        "TS_SMTP_FROM_EMAIL and TS_PUBLIC_BASE_URL. Any SMTP relay works — SES, "
        "SendGrid, Postmark, Mailgun, or your own.\n\n"
        f"To run without delivery anyway — local development and tests only — set "
        f"{ESCAPE_HATCH_ENV_VAR}=1. Never set it in a deployed environment: it "
        "does not make verification work, it only stops this message."
    )


def assert_email_delivery_is_usable(delivery: str, *, allow_undeliverable: bool = False) -> None:
    """Refuse to boot on a configuration that can never onboard a user.

    Same shape as the database-role check: a setting that cannot work is a
    deploy-time failure with an actionable message, not a service that starts
    cleanly and then refuses every login for a reason nobody connects to it.

    Deliberately does *not* offer "auto-verify when delivery is off" as the
    escape. That would silently disable the control that stops a stranger
    claiming an address they do not own, which is the thing verification exists
    to do — a broken deployment is a great deal better than a quietly insecure
    one.
    """
    if can_deliver(delivery):
        logger.info("email delivery configured", extra={"delivery": delivery})
        return

    if allow_undeliverable:
        # Deliberate, greppable opt-out. Logged at CRITICAL every boot so an
        # override left on by accident is visible rather than forgotten.
        logger.critical(
            "EMAIL DELIVERY DISABLED: no verification message can reach anyone "
            f"because {ESCAPE_HATCH_ENV_VAR} is set. Accounts cannot be verified, "
            "and an unverified account cannot log in — this service can onboard "
            "nobody. This must never be set in a deployed environment.",
            extra={"delivery": delivery, "event": "email_delivery_disabled"},
        )
        return

    raise UndeliverableEmailError(build_refusal_message(delivery))
