"""Every credential prefix this service mints has to be masked in logs.

Field-name redaction only catches values the caller filed under a name that
looks sensitive. A refresh token quoted inside a message, or filed under
``note``, matches no key pattern — so the value patterns have to know every
prefix. ``tsr_`` was missing from that list while ``tsa_`` and ``tse_`` were
there, which is exactly the shape of gap a test over the constants catches and a
test over one hand-picked example does not.
"""

from __future__ import annotations

import logging

import pytest

from threatsculpt.auth.refresh import REFRESH_TOKEN_PREFIX
from threatsculpt.auth.verification import VERIFICATION_TOKEN_PREFIX
from threatsculpt.observability.logging import REDACTED, JsonFormatter, scrub
from threatsculpt.security.tokens import AGENT_KEY_PREFIX, ENROLLMENT_TOKEN_PREFIX

#: Read from the modules that mint them, so a new prefix that nobody adds here
#: shows up as a failing test rather than as plaintext in the log stream.
ALL_PREFIXES = (
    AGENT_KEY_PREFIX,
    ENROLLMENT_TOKEN_PREFIX,
    REFRESH_TOKEN_PREFIX,
    VERIFICATION_TOKEN_PREFIX,
)

SUFFIX = "AbCdEf0123456789xyz"


@pytest.mark.parametrize("prefix", ALL_PREFIXES)
def test_a_credential_in_a_message_is_masked(prefix: str) -> None:
    secret = f"{prefix}{SUFFIX}"

    masked = scrub(f"presented {secret} on /auth/refresh")

    assert secret not in masked
    assert REDACTED in masked


@pytest.mark.parametrize("prefix", ALL_PREFIXES)
def test_a_credential_under_an_innocuous_field_name_is_masked(prefix: str) -> None:
    """``note`` matches no sensitive-key pattern, so only the value rule saves it."""
    secret = f"{prefix}{SUFFIX}"

    masked = scrub({"note": f"rotated {secret}"})

    assert secret not in str(masked)


@pytest.mark.parametrize("prefix", ALL_PREFIXES)
def test_a_credential_in_a_formatted_record_is_masked(prefix: str) -> None:
    secret = f"{prefix}{SUFFIX}"
    record = logging.LogRecord(
        name="threatsculpt.test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="credential %s was rejected",
        args=(secret,),
        exc_info=None,
    )

    assert secret not in JsonFormatter().format(record)
