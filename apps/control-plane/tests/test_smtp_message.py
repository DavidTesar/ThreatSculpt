"""What the message contains, and what it refuses to contain.

Header injection is the interesting case. Every value that reaches a header here
came from the database, which came from a validated registration — but "it was
validated somewhere else" is exactly the assumption that makes an injection bug
survive a refactor two layers away, so the boundary re-proves it.
"""

from __future__ import annotations

from email.message import EmailMessage

import pytest

from threatsculpt.auth.mail import (
    MAX_HEADER_FIELD_LENGTH,
    UnsafeMessageError,
    build_verification_email,
    validate_address,
    validate_base_url,
    verification_link,
)

TOKEN = "tsv_9Xk2mQpR7vT4wY8zA1bC3dE5fG6hJ0kL"

SENDER = "no-reply@threatsculpt.example"
RECIPIENT = "owner@customer.example"


def _build(**overrides: str) -> EmailMessage:
    values = {
        "from_address": SENDER,
        "from_name": "ThreatSculpt",
        "recipient": RECIPIENT,
        "org_slug": "acme-corp",
        "link": verification_link("https://app.example.com", TOKEN),
    }
    return build_verification_email(**{**values, **overrides})


# --- the link ---------------------------------------------------------------


def test_the_link_is_built_from_the_configured_public_origin() -> None:
    assert verification_link("https://app.example.com", TOKEN) == (
        f"https://app.example.com/verify-email?token={TOKEN}"
    )


def test_the_origin_may_carry_a_path_prefix() -> None:
    link = verification_link("https://example.com/console/", TOKEN)
    assert link.startswith("https://example.com/console/verify-email?token=")


def test_a_token_is_url_encoded_into_the_link() -> None:
    """Opaque tokens are URL-safe today; the link must not depend on that."""
    assert verification_link("https://app.example.com", "a b&c=d").endswith("token=a%20b%26c%3Dd")


@pytest.mark.parametrize(
    "base_url",
    [
        "javascript:alert(1)",
        "ftp://files.example.com",
        "app.example.com",
        "https://app.example.com/\nX-Injected: 1",
        "https://app.example.com?next=evil",
        "https://",
    ],
)
def test_an_unusable_public_origin_is_refused(base_url: str) -> None:
    with pytest.raises(UnsafeMessageError):
        validate_base_url(base_url)


# --- addresses --------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "owner@customer.example",
        "first.last+tag@sub.customer.example",
        "o'brien@customer.example",
    ],
)
def test_a_real_address_is_accepted(address: str) -> None:
    assert validate_address(address) == address


@pytest.mark.parametrize(
    "address",
    [
        "victim@example.com\nBcc: everyone@example.com",
        "victim@example.com\r\nBcc: everyone@example.com",
        "victim@example.com\rSubject: spoofed",
        "victim@example.com\x00",
        "victim@example.com, second@example.com",
        "Display Name <victim@example.com>",
        "victim@example.com Bcc: x@example.com",
        "no-at-sign.example.com",
        "@example.com",
        "victim@",
        "",
        "   ",
    ],
)
def test_an_injected_or_malformed_address_is_refused(address: str) -> None:
    with pytest.raises(UnsafeMessageError):
        validate_address(address)


def test_an_overlong_address_is_refused() -> None:
    with pytest.raises(UnsafeMessageError):
        validate_address(f"{'a' * 250}@example.com")


# --- header injection through the builder -----------------------------------


def test_an_injected_recipient_stops_the_whole_message() -> None:
    """Refused, not sanitised: a stripped address still mails the injector."""
    with pytest.raises(UnsafeMessageError):
        _build(recipient="victim@example.com\nBcc: everyone@example.com")


def test_an_injected_org_slug_stops_the_whole_message() -> None:
    """The slug is interpolated into the Subject header."""
    with pytest.raises(UnsafeMessageError):
        _build(org_slug="acme\r\nBcc: everyone@example.com")


def test_an_injected_sender_name_stops_the_whole_message() -> None:
    with pytest.raises(UnsafeMessageError):
        _build(from_name="ThreatSculpt\r\nX-Priority: 1")


def test_an_overlong_org_slug_stops_the_whole_message() -> None:
    with pytest.raises(UnsafeMessageError):
        _build(org_slug="a" * (MAX_HEADER_FIELD_LENGTH + 1))


def test_no_injected_header_survives_serialisation() -> None:
    """Belt and braces: the rendered bytes carry no header we did not write."""
    for hostile in ("victim@example.com\nBcc: x@example.com", "a@b.example\r\nX-Evil: 1"):
        with pytest.raises(UnsafeMessageError):
            _build(recipient=hostile)


# --- the rendered message ---------------------------------------------------


def test_the_message_is_plain_text_and_html() -> None:
    message = _build()
    assert message.get_content_type() == "multipart/alternative"
    subtypes = {part.get_content_subtype() for part in message.iter_parts()}
    assert subtypes == {"plain", "html"}


def test_both_parts_carry_the_verification_link() -> None:
    message = _build()
    link = verification_link("https://app.example.com", TOKEN)
    for part in message.iter_parts():
        assert link in part.get_content()


def test_the_headers_name_the_sender_the_recipient_and_the_org() -> None:
    message = _build()
    assert message["To"] == RECIPIENT
    assert SENDER in message["From"]
    assert "acme-corp" in message["Subject"]
    assert message["Auto-Submitted"] == "auto-generated"
    assert message["Message-ID"]
    assert message["Date"]


def test_html_from_the_org_slug_is_escaped_not_rendered() -> None:
    message = _build(org_slug="acme<script>alert(1)</script>")
    html_part = next(part for part in message.iter_parts() if part.get_content_subtype() == "html")
    body = html_part.get_content()
    assert "<script>" not in body
    assert "&lt;script&gt;" in body
