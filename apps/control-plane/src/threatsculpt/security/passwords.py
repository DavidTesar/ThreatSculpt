"""Argon2id password hashing.

Argon2id only — never bcrypt, never plaintext (docs/DATA-MODEL.md). The dummy
verification below is what makes login constant-time with respect to whether an
email exists: the unknown-user path burns the same Argon2 work as the
wrong-password path.
"""

from __future__ import annotations

import logging

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type

logger = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256

# OWASP Password Storage Cheat Sheet baseline for Argon2id (19 MiB, t=2, p=1).
_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19 * 1024,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

#: Hash of a value nobody can present, used to equalise timing on the
#: unknown-email path. Computed once at import.
_DUMMY_HASH = _HASHER.hash("threatsculpt-timing-equaliser-not-a-real-password")


def hash_password(password: str) -> str:
    """Argon2id hash, salt included in the encoded string."""
    return _HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-work verification. Returns False rather than raising."""
    try:
        _HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except (VerificationError, InvalidHashError):
        # A malformed stored hash is a data-integrity problem worth knowing
        # about, but it must not be distinguishable from a wrong password.
        logger.error("stored password hash could not be parsed", extra={"event": "bad_hash"})
        return False
    return True


def burn_dummy_verification() -> None:
    """Spend the same Argon2 work as a real verification, and discard it."""
    verify_password("threatsculpt-timing-equaliser-wrong", _DUMMY_HASH)


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash used weaker parameters than the current policy."""
    try:
        return _HASHER.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
