"""Structured JSON logging with secret redaction.

Two rules this module enforces mechanically, because "remember not to log the
password" is not a control:

1. Any log record *field* whose name looks sensitive is replaced with
   ``"[redacted]"`` before serialisation.
2. Any string value that looks like one of our credential formats
   (``tsa_``/``tse_``/``tsr_``/``tsv_`` credentials, JWTs) is masked wherever it appears.

Rule 2 exists because rule 1 only catches values the caller happened to file
under a sensitive-looking name. A refresh token quoted inside a message, or
filed under ``note``, is exactly as much of a credential and matches no key
pattern at all — so the prefix list here must cover every prefix
``security.tokens`` and ``auth.refresh`` can mint.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

from threatsculpt.observability.context import current_request_id

REDACTED = "[redacted]"

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(pass|passwd|password|secret|token|api_key|apikey|authorization|cookie|"
    r"credential|private_key|session|hash)",
    re.IGNORECASE,
)

_SECRET_VALUE_PATTERNS = (
    re.compile(r"\b(?:tsa|tse|tsr|tsv)_[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"),
)

_RESERVED_RECORD_FIELDS = frozenset(logging.LogRecord("", 0, "", 0, "", None, None).__dict__)


def scrub(value: Any, *, key: str | None = None) -> Any:
    """Return a redacted copy of ``value``. Never mutates the input."""
    if key is not None and _SENSITIVE_KEY_PATTERN.search(key):
        return REDACTED
    if isinstance(value, dict):
        return {str(k): scrub(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(item) for item in value]
    if isinstance(value, str):
        return _mask_secret_values(value)
    if isinstance(value, (int, float, bool, type(None))):
        return value
    return _mask_secret_values(str(value))


def _mask_secret_values(text: str) -> str:
    masked = text
    for pattern in _SECRET_VALUE_PATTERNS:
        masked = pattern.sub(REDACTED, masked)
    return masked


class JsonFormatter(logging.Formatter):
    """Emits one JSON object per record, with extras merged in and scrubbed."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": _mask_secret_values(record.getMessage()),
        }
        request_id = current_request_id()
        if request_id is not None:
            payload["request_id"] = request_id
        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_FIELDS or key.startswith("_"):
                continue
            payload[key] = scrub(value, key=key)
        if record.exc_info is not None:
            payload["exception"] = _mask_secret_values(self.formatException(record.exc_info))
        return json.dumps(payload, default=str, separators=(",", ":"))


class PlainFormatter(logging.Formatter):
    """Human-readable fallback for local development. Still redacts."""

    def format(self, record: logging.LogRecord) -> str:
        request_id = current_request_id() or "-"
        message = _mask_secret_values(record.getMessage())
        base = f"{record.levelname:<7} [{request_id}] {record.name}: {message}"
        if record.exc_info is not None:
            return f"{base}\n{_mask_secret_values(self.formatException(record.exc_info))}"
        return base


def configure_logging(*, level: str = "INFO", as_json: bool = True) -> None:
    """Install the root handler. Idempotent — safe to call per app creation."""
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter() if as_json else PlainFormatter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    # uvicorn duplicates access logs through its own handlers; let ours own them.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
