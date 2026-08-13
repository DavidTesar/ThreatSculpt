"""Where an outbound message goes. Deliberately not wired to anything.

This branch has no mail infrastructure, and inventing one is not what the
verification work is for. So delivery is a seam: the verification state machine
hands a finished message to an ``EmailSender`` and stops caring. Swapping in an
SES/SendGrid/SMTP implementation is one class and one settings value, and
touches nothing that decides whether an address is proved.

**Neither implementation here delivers mail.** ``NullEmailSender`` — the default,
and what production gets until somebody wires a real one — records that a message
was requested and drops it. That is a real operational gap and SECURITY.md says
so in as many words; it is not a gap in the model, which enforces verification
whether or not a message ever arrives.

The token is never logged. A verification token is a credential that grants
control of an account, so a sender that wrote it to the log stream would be a
credential in the log stream, which is precisely what ``observability.logging``
exists to prevent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

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
    """

    def send_verification(self, message: VerificationMessage) -> None: ...


class NullEmailSender:
    """Default. Logs that a message was wanted, delivers nothing, keeps nothing."""

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


#: Delivery modes that actually put a message in front of a human. Empty today,
#: which is the whole point of ``assert_email_delivery_is_usable``: an SMTP or
#: provider implementation adds its name here and the refusal below stops firing.
DELIVERING_MODES: frozenset[str] = frozenset()

ESCAPE_HATCH_ENV_VAR = "TS_ALLOW_UNDELIVERABLE_EMAIL"


class UndeliverableEmailError(RuntimeError):
    """No configured way to deliver a verification message, and no opt-out."""


def can_deliver(delivery: str) -> bool:
    return delivery in DELIVERING_MODES


def build_email_sender(delivery: str) -> EmailSender:
    """Resolve the configured sender. Unknown values fail closed, not open."""
    if delivery == "memory":
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
        "Wire a delivery mechanism: implement EmailSender in "
        "threatsculpt/auth/delivery.py, add its name to DELIVERING_MODES, and set "
        "TS_EMAIL_DELIVERY to it.\n\n"
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
