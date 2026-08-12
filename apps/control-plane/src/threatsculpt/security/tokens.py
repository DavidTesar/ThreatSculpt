"""Opaque credential generation, SHA-256 storage hashing, and JWT access tokens.

Opaque credentials (refresh tokens, agent API keys, enrollment tokens) are
random bytes. They are stored as a SHA-256 hex digest and compared with
``hmac.compare_digest``. SHA-256 rather than Argon2 is correct here precisely
because these are high-entropy random values, not user-chosen passwords: there
is nothing to brute-force, and a per-request Argon2 verification on the agent
hot path would be a self-inflicted denial of service.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from uuid import UUID, uuid4

import jwt
from jwt.exceptions import InvalidTokenError

from threatsculpt.core.errors import AuthenticationError

AGENT_KEY_PREFIX: Final = "tsa_"
ENROLLMENT_TOKEN_PREFIX: Final = "tse_"  # noqa: S105 - a prefix, not a credential
REFRESH_TOKEN_BYTES: Final = 32
KEY_PREFIX_DISPLAY_LENGTH: Final = 8

ACCESS_TOKEN_TYPE: Final = "access"  # noqa: S105 - a claim value, not a credential


def generate_opaque_token(prefix: str = "", *, num_bytes: int = REFRESH_TOKEN_BYTES) -> str:
    return f"{prefix}{secrets.token_urlsafe(num_bytes)}"


def hash_token(token: str) -> str:
    """SHA-256 hex digest — the only form ever written to the database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(candidate_hash: str, stored_hash: str) -> bool:
    return hmac.compare_digest(candidate_hash, stored_hash)


def key_prefix_of(token: str) -> str:
    """First 8 characters, for display and support lookup. Not a secret."""
    return token[:KEY_PREFIX_DISPLAY_LENGTH]


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    """Validated claims from an access token. Frozen — decoding yields a value."""

    user_id: UUID
    org_id: UUID
    role: str
    jti: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class JwtCodec:
    """Encodes and decodes access tokens for one secret/algorithm pair."""

    secret: str
    algorithm: str
    ttl: timedelta
    issuer: str = "threatsculpt"

    def encode(self, *, user_id: UUID, org_id: UUID, role: str) -> tuple[str, datetime]:
        now = datetime.now(tz=UTC)
        expires_at = now + self.ttl
        payload: dict[str, Any] = {
            "sub": str(user_id),
            "org": str(org_id),
            "role": role,
            "typ": ACCESS_TOKEN_TYPE,
            "jti": uuid4().hex,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": self.issuer,
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm), expires_at

    def decode(self, token: str) -> AccessTokenClaims:
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub", "iss"]},
            )
        except InvalidTokenError as exc:
            raise AuthenticationError("Access token is invalid or expired.") from exc

        if payload.get("typ") != ACCESS_TOKEN_TYPE:
            # A refresh token must never be accepted where an access token is
            # expected, even though both are signed by us.
            raise AuthenticationError("Access token is invalid or expired.")

        try:
            return AccessTokenClaims(
                user_id=UUID(payload["sub"]),
                org_id=UUID(payload["org"]),
                role=str(payload["role"]),
                jti=str(payload.get("jti", "")),
                expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise AuthenticationError("Access token is invalid or expired.") from exc
