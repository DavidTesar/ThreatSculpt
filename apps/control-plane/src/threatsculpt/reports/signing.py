"""Short-lived signed download URLs.

A report is fetched by a browser following a link, which cannot attach an
``Authorization`` header — that is the whole reason signed URLs exist. So the
capability travels in the URL, and everything that makes that safe is here:

* The signature covers the org id as well as the report id, and the download
  handler scopes its query to the signed org. A tampered report id therefore
  cannot reach another tenant's row; it reaches a 404.
* HMAC-SHA256 over the exact payload string, compared with
  ``hmac.compare_digest`` so a wrong signature cannot be recovered by timing.
* A five-minute expiry, checked server-side. A URL that leaks into a proxy log
  or a chat message is worthless within minutes.

The signing key is the process's JWT secret. Same trust boundary, same rotation
story, one fewer secret to manage badly.
"""

from __future__ import annotations

import base64
import hmac
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Final
from uuid import UUID

from threatsculpt.core.errors import AuthenticationError

#: Long enough for a browser to follow a redirect and start a download; short
#: enough that a leaked URL is not a durable credential.
DOWNLOAD_TTL_SECONDS: Final = 300

_SEPARATOR: Final = "."
_FIELD_SEPARATOR: Final = ":"


@dataclass(frozen=True, slots=True)
class DownloadGrant:
    report_id: UUID
    org_id: UUID
    expires_at: int


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _payload(report_id: UUID, org_id: UUID, expires_at: int) -> str:
    return _FIELD_SEPARATOR.join((str(report_id), str(org_id), str(expires_at)))


def _signature(secret: str, payload: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), sha256).digest()
    return _b64(digest)


def sign_download(
    secret: str, report_id: UUID, org_id: UUID, *, ttl_seconds: int = DOWNLOAD_TTL_SECONDS
) -> str:
    expires_at = int(time.time()) + ttl_seconds
    payload = _payload(report_id, org_id, expires_at)
    return f"{_b64(payload.encode('utf-8'))}{_SEPARATOR}{_signature(secret, payload)}"


def verify_download(secret: str, token: str) -> DownloadGrant:
    """Return the grant a valid token carries, or raise.

    Every failure raises the same error with the same message. Distinguishing
    "expired" from "forged" would tell an attacker which half of the token to
    keep working on.
    """
    encoded, separator, signature = token.partition(_SEPARATOR)
    if not separator or not encoded or not signature:
        raise AuthenticationError("This download link is invalid or has expired.")

    try:
        payload = _unb64(encoded).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthenticationError("This download link is invalid or has expired.") from exc

    if not hmac.compare_digest(signature, _signature(secret, payload)):
        raise AuthenticationError("This download link is invalid or has expired.")

    return _parse(payload)


def _parse(payload: str) -> DownloadGrant:
    parts = payload.split(_FIELD_SEPARATOR)
    if len(parts) != 3:
        raise AuthenticationError("This download link is invalid or has expired.")
    try:
        grant = DownloadGrant(
            report_id=UUID(parts[0]), org_id=UUID(parts[1]), expires_at=int(parts[2])
        )
    except ValueError as exc:
        raise AuthenticationError("This download link is invalid or has expired.") from exc

    if grant.expires_at < int(time.time()):
        raise AuthenticationError("This download link is invalid or has expired.")
    return grant
