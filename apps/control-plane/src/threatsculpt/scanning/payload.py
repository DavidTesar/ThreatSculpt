"""Reading a result submission without trusting its size.

FastAPI would happily buffer a multi-gigabyte body into memory before any
handler code runs, so the 10 MB cap in docs/AGENT-PROTOCOL.md §5 has to be
applied to the *stream*, not to the parsed object. The ``Content-Length`` header
is checked first because it lets an oversized request be refused before a byte of
it is read, and the stream is then counted anyway because a chunked request has
no such header — and a lying one is exactly the request worth stopping.
"""

from __future__ import annotations

from fastapi import Request
from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError

from threatsculpt.core.errors import ValidationError
from threatsculpt.scanning.errors import PayloadTooLargeError


async def read_capped_body(request: Request, cap: int) -> bytes:
    """The request body, or ``PayloadTooLargeError`` before it is fully read."""
    if _declared_length(request) > cap:
        raise PayloadTooLargeError()

    chunks: list[bytes] = []
    seen = 0
    async for chunk in request.stream():
        seen += len(chunk)
        if seen > cap:
            raise PayloadTooLargeError()
        chunks.append(chunk)
    return b"".join(chunks)


def _declared_length(request: Request) -> int:
    """``Content-Length``, or 0 when absent or unparseable.

    An unparseable header is not treated as an error: the stream count below is
    the authority, and rejecting on a malformed header would only add a second
    way to fail on a request that is about to be measured properly anyway.
    """
    declared = request.headers.get("content-length")
    if declared is None:
        return 0
    try:
        return int(declared)
    except ValueError:
        return 0


def parse_body[ModelT: BaseModel](model: type[ModelT], body: bytes) -> ModelT:
    """Validate raw bytes against a pydantic model.

    Used instead of a declared body parameter because the cap above has already
    consumed the stream. The rejection is reshaped into the application's own
    ``ValidationError`` so the response envelope and the field naming match every
    other 400 the API produces.
    """
    try:
        return model.model_validate_json(body)
    except PydanticValidationError as exc:
        errors = exc.errors()
        if not errors:  # pragma: no cover - pydantic always reports at least one
            raise ValidationError() from exc
        first = errors[0]
        field = ".".join(str(part) for part in first["loc"]) or None
        raise ValidationError(str(first["msg"]), field=field) from exc
