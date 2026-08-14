"""Turning the process environment into a usable SMTP configuration, or refusing.

SMTP rather than a vendor SDK because the same nine settings reach SES,
SendGrid, Postmark, Mailgun and the corporate relay an enterprise customer will
insist on using instead of any of them. A vendor SDK would be a bet on which one
every future customer picks.

**Every problem is reported at once.** An operator wiring a relay for the first
time typically has two or three of these wrong, and a check that stops at the
first one turns that into three deploys.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import SecretStr

from threatsculpt.auth.mail import (
    UnsafeMessageError,
    safe_header_value,
    validate_address,
    validate_base_url,
)
from threatsculpt.config import Settings

TlsMode = Literal["starttls", "implicit", "none"]

#: Hosts for which unencrypted SMTP is permitted. Anywhere else the session
#: carries a relay password and a verification link — a credential and a
#: credential-bearing URL — across a network in the clear.
LOOPBACK_HOSTS = frozenset({"localhost", "localhost.localdomain", "127.0.0.1", "::1", "[::1]"})


class SmtpConfigurationError(RuntimeError):
    """The SMTP settings cannot deliver mail. Raised at boot, never at send."""


@dataclass(frozen=True, slots=True)
class SmtpConfig:
    """A validated relay configuration. Immutable, and prints no password.

    ``password`` stays a ``SecretStr`` all the way down to ``smtplib.login`` so
    that a stray repr, a logged dataclass or a traceback frame shows
    ``SecretStr('**********')`` rather than the relay credential.
    """

    host: str
    port: int
    tls: TlsMode
    username: str | None
    password: SecretStr | None
    timeout_seconds: float
    from_address: str
    from_name: str
    base_url: str
    verify_on_start: bool

    @property
    def is_loopback(self) -> bool:
        return self.host.lower() in LOOPBACK_HOSTS


def build_smtp_config(settings: Settings) -> SmtpConfig:
    """Validate the SMTP settings into a config, or raise with every problem.

    Runs at boot, from ``build_email_sender``. A setting that can never work is
    a deploy-time failure here for the same reason the database-role check is
    one: the alternative is a service that starts cleanly and silently onboards
    nobody, because the only symptom is a message that never arrives.
    """
    problems = _collect_problems(settings)
    if problems:
        raise SmtpConfigurationError(_refusal(problems))

    # Every value below was proved present and well-formed by _collect_problems.
    return SmtpConfig(
        host=(settings.smtp_host or "").strip(),
        port=settings.smtp_port,
        tls=settings.smtp_tls,
        username=(settings.smtp_username or "").strip() or None,
        password=settings.smtp_password,
        timeout_seconds=settings.smtp_timeout_seconds,
        from_address=validate_address(settings.smtp_from_email or "", field="TS_SMTP_FROM_EMAIL"),
        from_name=settings.smtp_from_name,
        base_url=validate_base_url(settings.public_base_url or "", field="TS_PUBLIC_BASE_URL"),
        verify_on_start=settings.smtp_verify_on_start,
    )


def _collect_problems(settings: Settings) -> tuple[str, ...]:
    """Every reason this configuration cannot deliver, in one pass."""
    return (
        *_host_problems(settings),
        *_credential_problems(settings),
        *_address_problems(settings),
        *_link_problems(settings),
    )


def _host_problems(settings: Settings) -> tuple[str, ...]:
    host = (settings.smtp_host or "").strip()
    if not host:
        return ("TS_SMTP_HOST is not set, so there is no relay to hand a message to.",)
    if settings.smtp_tls != "none" or host.lower() in LOOPBACK_HOSTS:
        return ()
    return (
        f"TS_SMTP_TLS=none is only permitted for a loopback relay, and "
        f"TS_SMTP_HOST={host!r} is not one. Unencrypted SMTP to a remote host puts "
        "the relay password and the verification link — which is itself a "
        "credential — on the wire in the clear. Use 'starttls' (port 587) or "
        "'implicit' (port 465).",
    )


def _credential_problems(settings: Settings) -> tuple[str, ...]:
    username = (settings.smtp_username or "").strip()
    has_password = settings.smtp_password is not None
    if username and not has_password:
        return ("TS_SMTP_USERNAME is set but TS_SMTP_PASSWORD is not.",)
    if has_password and not username:
        return ("TS_SMTP_PASSWORD is set but TS_SMTP_USERNAME is not.",)
    return ()


def _address_problems(settings: Settings) -> tuple[str, ...]:
    """The sender address and its display name, both of which reach a header."""
    if not (settings.smtp_from_email or "").strip():
        return ("TS_SMTP_FROM_EMAIL is not set, so the message has no envelope sender.",)
    try:
        validate_address(settings.smtp_from_email or "", field="TS_SMTP_FROM_EMAIL")
        # Checked here rather than only at render time: a display name that
        # cannot go in a header would otherwise refuse every send, at runtime,
        # one registration at a time.
        safe_header_value(settings.smtp_from_name, field="TS_SMTP_FROM_NAME")
    except UnsafeMessageError as exc:
        return (str(exc),)
    return ()


def _link_problems(settings: Settings) -> tuple[str, ...]:
    raw = (settings.public_base_url or "").strip()
    if not raw:
        return (
            "TS_PUBLIC_BASE_URL is not set, so no verification link could be built. "
            "Set it to the dashboard's public origin, e.g. https://app.example.com.",
        )
    try:
        base = validate_base_url(raw, field="TS_PUBLIC_BASE_URL")
    except UnsafeMessageError as exc:
        return (str(exc),)
    if settings.is_production and not base.startswith("https://"):
        return (
            "TS_PUBLIC_BASE_URL must be https in production: the verification link "
            "carries a token that grants control of the account, and over http it "
            "is readable by anything on the path.",
        )
    return ()


def _refusal(problems: tuple[str, ...]) -> str:
    listed = "\n".join(f"  - {problem}" for problem in problems)
    return (
        "TS_EMAIL_DELIVERY='smtp' is selected but the SMTP settings cannot deliver "
        f"a message:\n{listed}\n\n"
        "Verification is enforced, so an account that never receives its message "
        "can never sign in. Fix the settings above, or select a different "
        "TS_EMAIL_DELIVERY — see SECURITY.md."
    )
