"""Logging with a hard redaction filter.

The agent handles two secret shapes: enrollment tokens (``tse_...``) and API keys
(``tsa_...``). Nothing else in the process is sensitive. The filter below scrubs both
from every record — message, args, and formatted exception text — so an accidental
``log.debug("headers=%s", headers)`` cannot leak a credential.

Redaction is a backstop, not the primary control: call sites do not log secrets at all.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

REDACTED = "***REDACTED***"

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ts[ae]_[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?\S+"),
    re.compile(r"(?i)(api[_-]?key\"?\s*[:=]\s*\"?)[^\s\",}]+"),
)


def redact(text: str) -> str:
    """Replace anything that looks like an agent credential with a placeholder."""
    scrubbed = _SECRET_PATTERNS[0].sub(REDACTED, text)
    scrubbed = _SECRET_PATTERNS[1].sub(rf"\1{REDACTED}", scrubbed)
    return _SECRET_PATTERNS[2].sub(rf"\1{REDACTED}", scrubbed)


class SecretRedactingFilter(logging.Filter):
    """Scrubs credentials from every record that passes through a handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            record.args = _redact_args(record.args)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def _redact_args(args: Any) -> Any:
    if isinstance(args, dict):
        return {key: _redact_value(value) for key, value in args.items()}
    if isinstance(args, tuple):
        return tuple(_redact_value(value) for value in args)
    return _redact_value(args)


def _redact_value(value: Any) -> Any:
    return redact(value) if isinstance(value, str) else value


def configure_logging(level: str = "INFO", stream: Any = None) -> None:
    """Install a single stderr handler carrying the redaction filter."""
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s")
    )
    handler.addFilter(SecretRedactingFilter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    # httpx logs full request URLs at INFO; they carry no secret, but keep the noise down.
    logging.getLogger("httpx").setLevel(logging.WARNING)
