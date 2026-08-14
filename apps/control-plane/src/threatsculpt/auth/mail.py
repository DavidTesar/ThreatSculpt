"""Rendering a verification message, and the header-safety rules around it.

Two things are dangerous about turning stored values into an email:

1. **Header injection.** A header is terminated by CRLF, so a value carrying one
   does not land *in* a header — it ends the header and starts another. An
   address of ``victim@example.com\\nBcc: everyone@example.com`` turns this
   service into a relay pointed wherever the injector likes. Every value that
   reaches a header is therefore proved safe here and the message is refused
   outright if it cannot be, rather than sanitised into something that looks
   fine and is not.

2. **The token is a credential.** It grants control of an account, so the link
   built from it is a credential too. Nothing in this module logs, and callers
   must not log what it returns — see the note in ``auth.delivery``.

Nothing here performs I/O: rendering is a pure function of its inputs, so the
injection cases are testable without a mail server anywhere in sight.
"""

from __future__ import annotations

import html
import re
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from urllib.parse import quote, urlsplit

#: RFC 5321's limit on a reverse-path. Also a cheap bound on anything that
#: reaches a header from the database.
MAX_ADDRESS_LENGTH = 254

#: Applied to every other interpolated field. Long enough for any real value,
#: short enough that a header cannot be used as a payload carrier.
MAX_HEADER_FIELD_LENGTH = 128

#: Path appended to the configured public origin. The origin may itself carry a
#: prefix (``https://app.example.com/console``), so this stays a constant.
VERIFICATION_PATH = "/verify-email"

_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})

# Deliberately stricter than RFC 5322: no quoted local parts, no comments, no
# bracketed address literals. Every address this service sends to came through
# pydantic's EmailStr at registration, so anything exotic enough to fail here is
# far more likely to be an injection attempt than a real mailbox.
_ADDRESS_PATTERN = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
    r"\.[A-Za-z]{2,63}$"
)

# C0, DEL and C1. CR and LF are the injection vector; the rest have no business
# in a header and their presence means the value did not come from a real form.
_CONTROL_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class UnsafeMessageError(ValueError):
    """A value bound for a header could not be proved safe, so nothing is sent.

    Refusing beats stripping: a stripped value still delivers whatever the
    injector wanted delivered, minus the part that was noticed.
    """


def validate_address(raw: str, *, field: str = "recipient") -> str:
    """Return ``raw`` proved safe to place in an address header, or raise."""
    candidate = raw.strip()
    if not candidate:
        raise UnsafeMessageError(f"{field} address is empty")
    if len(candidate) > MAX_ADDRESS_LENGTH:
        raise UnsafeMessageError(f"{field} address exceeds {MAX_ADDRESS_LENGTH} characters")
    if _CONTROL_PATTERN.search(candidate):
        raise UnsafeMessageError(f"{field} address contains a control character")
    if not _ADDRESS_PATTERN.fullmatch(candidate):
        raise UnsafeMessageError(f"{field} address is not a plain addr-spec")
    return candidate


def safe_header_value(raw: str, *, field: str) -> str:
    """Return ``raw`` proved safe to interpolate into a header, or raise."""
    if _CONTROL_PATTERN.search(raw):
        raise UnsafeMessageError(f"{field} contains a control character")
    if len(raw) > MAX_HEADER_FIELD_LENGTH:
        raise UnsafeMessageError(f"{field} exceeds {MAX_HEADER_FIELD_LENGTH} characters")
    return raw


def validate_base_url(raw: str, *, field: str = "public base URL") -> str:
    """Return the public origin with any trailing slash removed, or raise.

    Checked because the verification link is built from it: a base URL carrying
    a control character would put one in the message body, and a non-HTTP scheme
    would produce a link that either does not work or does something else
    entirely.
    """
    candidate = raw.strip()
    if _CONTROL_PATTERN.search(candidate) or " " in candidate:
        raise UnsafeMessageError(f"{field} contains whitespace or a control character")
    parts = urlsplit(candidate)
    if parts.scheme not in _ALLOWED_URL_SCHEMES:
        raise UnsafeMessageError(f"{field} must start with http:// or https://")
    if not parts.netloc:
        raise UnsafeMessageError(f"{field} has no host")
    if parts.query or parts.fragment:
        raise UnsafeMessageError(f"{field} must not carry a query string or fragment")
    return candidate.rstrip("/")


def verification_link(base_url: str, token: str) -> str:
    """The URL the recipient follows. Carries a credential — never log it."""
    return f"{validate_base_url(base_url)}{VERIFICATION_PATH}?token={quote(token, safe='')}"


def build_verification_email(
    *,
    from_address: str,
    from_name: str,
    recipient: str,
    org_slug: str,
    link: str,
) -> EmailMessage:
    """Render the multipart message. Raises before building anything unsafe."""
    sender = validate_address(from_address, field="sender")
    to = validate_address(recipient)
    display_name = safe_header_value(from_name, field="sender name")
    org = safe_header_value(org_slug, field="org_slug")

    message = EmailMessage()
    message["From"] = formataddr((display_name, sender))
    message["To"] = to
    message["Subject"] = f"Verify your email address for {org}"
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain=sender.rpartition("@")[2])
    # Stops an out-of-office autoresponder answering, and answering, and
    # answering. Cheap, and the alternative is a mail loop with a customer.
    message["Auto-Submitted"] = "auto-generated"

    message.set_content(_plain_body(org, link))
    message.add_alternative(_html_body(org, link), subtype="html")
    return message


def _plain_body(org_slug: str, link: str) -> str:
    return (
        f"Someone registered the organisation '{org_slug}' on ThreatSculpt with "
        "this email address.\n\n"
        "Open the link below to prove you control this address. Until you do, "
        "the account cannot sign in.\n\n"
        f"{link}\n\n"
        "The link expires. If it no longer works, sign in and request a new one.\n\n"
        "If you did not register, you can ignore this message — the address has "
        "not been used for anything, and it never will be unless somebody opens "
        "the link above.\n"
    )


def _html_body(org_slug: str, link: str) -> str:
    # Escaped rather than trusted: `link` is built here and `org_slug` came from
    # the database, and neither is a reason to hand raw text to a mail client
    # that will render it.
    safe_org = html.escape(org_slug)
    safe_link = html.escape(link, quote=True)
    return (
        '<html><body style="font-family:system-ui,sans-serif;line-height:1.5">'
        f"<p>Someone registered the organisation <strong>{safe_org}</strong> on "
        "ThreatSculpt with this email address.</p>"
        "<p>Open the link below to prove you control this address. Until you do, "
        "the account cannot sign in.</p>"
        f'<p><a href="{safe_link}">Verify this email address</a></p>'
        f"<p>If the link does not work, copy this into your browser:<br>"
        f"<code>{safe_link}</code></p>"
        "<p>The link expires. If it no longer works, sign in and request a new one.</p>"
        "<p>If you did not register, you can ignore this message — the address has "
        "not been used for anything, and it never will be unless somebody opens "
        "the link above.</p>"
        "</body></html>"
    )
