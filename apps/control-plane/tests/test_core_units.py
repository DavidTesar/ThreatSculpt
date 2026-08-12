"""Unit tests for the cross-cutting pieces: config, redaction, limits, tokens."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError as PydanticValidationError

from threatsculpt.config import Settings
from threatsculpt.core.envelope import PageMeta, error_payload, ok
from threatsculpt.core.errors import AuthenticationError, NotFoundError, RateLimitedError
from threatsculpt.core.pagination import MAX_PER_PAGE, PaginationParams
from threatsculpt.db.dsn import dsn_from_environment, normalise_driver
from threatsculpt.observability.logging import REDACTED, JsonFormatter, scrub
from threatsculpt.security import passwords
from threatsculpt.security.ratelimit import SlidingWindowLimiter
from threatsculpt.security.tokens import (
    AGENT_KEY_PREFIX,
    JwtCodec,
    generate_opaque_token,
    hash_token,
    key_prefix_of,
    tokens_match,
)

VALID_SECRET = "a" * 40
VALID_DSN = "postgresql://user:pw@localhost:5432/db"


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {"database_url": VALID_DSN, "jwt_secret": VALID_SECRET}
    return Settings(**(base | overrides))  # type: ignore[arg-type]


# --- config ---------------------------------------------------------------


def test_settings_reject_a_short_jwt_secret() -> None:
    with pytest.raises(PydanticValidationError, match="at least 32 characters"):
        _settings(jwt_secret="too-short")


def test_settings_reject_a_wildcard_cors_origin() -> None:
    with pytest.raises(PydanticValidationError, match="must not contain"):
        _settings(cors_origins="*")


def test_settings_split_comma_separated_origins() -> None:
    settings = _settings(cors_origins="http://a.example, http://b.example")

    assert settings.cors_origins == ("http://a.example", "http://b.example")


def test_settings_do_not_expose_secrets_in_repr() -> None:
    settings = _settings()

    assert VALID_SECRET not in repr(settings)
    assert "pw" not in repr(settings.database_url)


def test_database_url_gets_the_psycopg_driver() -> None:
    assert normalise_driver(VALID_DSN).startswith("postgresql+psycopg://")
    assert normalise_driver("postgresql+asyncpg://h/d") == "postgresql+psycopg://h/d"


def test_database_url_without_a_scheme_is_rejected() -> None:
    with pytest.raises(ValueError, match="full DSN"):
        normalise_driver("just-a-host")


def test_dsn_from_environment_prefers_the_project_variable() -> None:
    env = {"TS_DATABASE_URL": "postgresql://ts/db", "DATABASE_URL": "postgresql://generic/db"}

    assert dsn_from_environment(env) == "postgresql://ts/db"


def test_dsn_from_environment_falls_back_to_the_conventional_variable() -> None:
    """CI systems and deploy platforms inject DATABASE_URL, not TS_DATABASE_URL."""
    assert dsn_from_environment({"DATABASE_URL": "postgresql://generic/db"}) == (
        "postgresql://generic/db"
    )


def test_dsn_from_environment_ignores_blank_values() -> None:
    assert dsn_from_environment({"TS_DATABASE_URL": "  ", "DATABASE_URL": ""}) is None


def test_dsn_resolution_does_not_import_application_settings() -> None:
    """Migrations must not need the JWT secret to apply a schema.

    ``migrations/env.py`` imports ``threatsculpt.db.dsn``. If that module ever
    pulled in ``threatsculpt.config``, importing it would drag in the settings
    model and running a migration would start demanding the application's
    secrets again. Checked against the real import graph in a fresh interpreter
    rather than by grepping the source, so a mention in a comment cannot fail it
    and a transitive import cannot slip past it.
    """
    probe = "import sys; import threatsculpt.db.dsn; print('threatsculpt.config' in sys.modules)"

    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": os.environ.get("PATH", "")},
    )

    assert result.stdout.strip() == "False"


# --- redaction ------------------------------------------------------------


@pytest.mark.parametrize(
    "key", ["password", "Password", "api_key", "authorization", "token_hash", "cookie"]
)
def test_sensitive_keys_are_redacted(key: str) -> None:
    assert scrub({key: "hunter2"}) == {key: REDACTED}


def test_redaction_recurses_into_nested_structures() -> None:
    payload = {"user": {"email": "a@b.example", "password": "hunter2"}, "items": [{"token": "x"}]}

    assert scrub(payload) == {
        "user": {"email": "a@b.example", "password": REDACTED},
        "items": [{"token": REDACTED}],
    }


def test_redaction_does_not_mutate_the_input() -> None:
    original = {"password": "hunter2"}

    scrub(original)

    assert original == {"password": "hunter2"}


@pytest.mark.parametrize(
    "value",
    [
        "tsa_abcdefghijklmnop",
        "tse_abcdefghijklmnop",
        "Bearer eyJhbGciOiJIUzI1NiJ9",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature",
    ],
)
def test_credential_shaped_values_are_masked_anywhere_they_appear(value: str) -> None:
    assert REDACTED in scrub(f"failed for {value} at step 2")


def test_json_formatter_emits_one_object_and_redacts_extras() -> None:
    record = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="login for %s",
        args=("a@b.example",),
        exc_info=None,
    )
    record.password = "hunter2"
    record.org_id = "abc"

    payload = json.loads(JsonFormatter().format(record))

    assert payload["message"] == "login for a@b.example"
    assert payload["password"] == REDACTED
    assert payload["org_id"] == "abc"
    assert payload["level"] == "INFO"


def test_json_formatter_masks_a_token_in_the_message_itself() -> None:
    record = logging.LogRecord(
        name="t",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="key tsa_supersecretvalue rejected",
        args=(),
        exc_info=None,
    )

    payload = json.loads(JsonFormatter().format(record))

    assert "tsa_supersecretvalue" not in payload["message"]


# --- pagination -----------------------------------------------------------


def test_pagination_computes_limit_and_offset() -> None:
    params = PaginationParams(page=3, per_page=25)

    assert (params.limit, params.offset) == (25, 50)


@pytest.mark.parametrize(
    ("page", "per_page"), [(0, 50), (-1, 50), (1, 0), (1, MAX_PER_PAGE + 1), (1, -5)]
)
def test_pagination_rejects_out_of_range_values(page: int, per_page: int) -> None:
    with pytest.raises(ValueError):
        PaginationParams(page=page, per_page=per_page)


def test_pagination_meta_carries_the_total() -> None:
    assert PaginationParams(page=2, per_page=10).meta(213) == PageMeta(
        page=2, per_page=10, total=213
    )


# --- envelope -------------------------------------------------------------


def test_success_envelope_has_a_null_error() -> None:
    envelope = ok({"id": 1}, meta=PageMeta(page=1, per_page=50, total=1))

    assert envelope.error is None
    assert envelope.data == {"id": 1}
    assert envelope.meta is not None


def test_error_payload_shape_matches_the_contract() -> None:
    assert error_payload("network_not_authorized", "Scans require it.", "network_id") == {
        "data": None,
        "error": {
            "code": "network_not_authorized",
            "message": "Scans require it.",
            "field": "network_id",
        },
    }


def test_error_status_codes() -> None:
    assert NotFoundError().status_code == 404
    assert AuthenticationError().status_code == 401
    assert RateLimitedError(retry_after_seconds=30).retry_after_seconds == 30


# --- rate limiter ---------------------------------------------------------


def test_limiter_allows_up_to_the_limit_then_refuses() -> None:
    limiter = SlidingWindowLimiter()

    allowed = [limiter.check("ip:1.2.3.4", 10, now=100.0).allowed for _ in range(10)]
    refused = limiter.check("ip:1.2.3.4", 10, now=100.0)

    assert all(allowed)
    assert refused.allowed is False
    assert refused.retry_after_seconds > 0


def test_limiter_window_slides() -> None:
    limiter = SlidingWindowLimiter()
    for _ in range(10):
        limiter.check("k", 10, now=100.0)

    assert limiter.check("k", 10, now=100.5).allowed is False
    assert limiter.check("k", 10, now=161.0).allowed is True


def test_limiter_keys_are_independent() -> None:
    limiter = SlidingWindowLimiter()
    for _ in range(10):
        limiter.check("a", 10, now=100.0)

    assert limiter.check("b", 10, now=100.0).allowed is True


def test_limiter_prune_drops_stale_buckets() -> None:
    limiter = SlidingWindowLimiter()
    limiter.check("k", 10, now=100.0)

    limiter.prune(now=1000.0)

    assert limiter.check("k", 1, now=1000.0).allowed is True


# --- passwords ------------------------------------------------------------


def test_hashes_are_argon2id_and_salted() -> None:
    first = passwords.hash_password("correct-horse-battery-staple")
    second = passwords.hash_password("correct-horse-battery-staple")

    assert first.startswith("$argon2id$")
    assert first != second


def test_verify_accepts_the_right_password_and_rejects_others() -> None:
    stored = passwords.hash_password("correct-horse-battery-staple")

    assert passwords.verify_password("correct-horse-battery-staple", stored) is True
    assert passwords.verify_password("wrong", stored) is False


def test_verify_returns_false_for_a_corrupt_hash_rather_than_raising() -> None:
    assert passwords.verify_password("anything", "not-a-hash") is False


def test_bcrypt_hashes_are_not_accepted() -> None:
    """Never bcrypt — a legacy hash must fail closed, not verify."""
    bcrypt_hash = "$2b$12$KIXQJ0k7uPa1sB1e9Z1r8u1a1b1c1d1e1f1g1h1i1j1k1l1m1n1o1"

    assert passwords.verify_password("anything", bcrypt_hash) is False


# --- tokens ---------------------------------------------------------------


def test_opaque_tokens_are_unique_and_prefixed() -> None:
    first = generate_opaque_token(AGENT_KEY_PREFIX)
    second = generate_opaque_token(AGENT_KEY_PREFIX)

    assert first.startswith(AGENT_KEY_PREFIX)
    assert first != second
    assert len(key_prefix_of(first)) == 8


def test_token_hash_is_sha256_hex_and_stable() -> None:
    digest = hash_token("tsa_example")

    assert len(digest) == 64
    assert digest == hash_token("tsa_example")
    assert tokens_match(digest, hash_token("tsa_example")) is True
    assert tokens_match(digest, hash_token("tsa_other")) is False


def test_jwt_round_trip_preserves_the_claims() -> None:
    codec = JwtCodec(secret=VALID_SECRET, algorithm="HS256", ttl=timedelta(minutes=15))
    user_id, org_id = uuid4(), uuid4()

    token, expires_at = codec.encode(user_id=user_id, org_id=org_id, role="admin")
    claims = codec.decode(token)

    assert (claims.user_id, claims.org_id, claims.role) == (user_id, org_id, "admin")
    assert claims.expires_at.replace(microsecond=0) == expires_at.replace(microsecond=0)


def test_jwt_signed_with_another_secret_is_rejected() -> None:
    minted = JwtCodec(secret="b" * 40, algorithm="HS256", ttl=timedelta(minutes=15))
    ours = JwtCodec(secret=VALID_SECRET, algorithm="HS256", ttl=timedelta(minutes=15))
    token, _ = minted.encode(user_id=uuid4(), org_id=uuid4(), role="owner")

    with pytest.raises(AuthenticationError):
        ours.decode(token)


def test_expired_jwt_is_rejected() -> None:
    codec = JwtCodec(secret=VALID_SECRET, algorithm="HS256", ttl=timedelta(minutes=-1))
    token, _ = codec.encode(user_id=uuid4(), org_id=uuid4(), role="owner")

    with pytest.raises(AuthenticationError):
        codec.decode(token)


def test_garbage_is_rejected_as_a_jwt() -> None:
    codec = JwtCodec(secret=VALID_SECRET, algorithm="HS256", ttl=timedelta(minutes=15))

    with pytest.raises(AuthenticationError):
        codec.decode("not.a.jwt")


def test_cors_origins_parse_from_a_comma_separated_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: pydantic-settings JSON-decodes tuple fields by default.

    Without ``NoDecode`` the documented ``.env`` form aborts start-up with a
    SettingsError instead of producing a list of origins.
    """
    monkeypatch.setenv("TS_DATABASE_URL", VALID_DSN)
    monkeypatch.setenv("TS_JWT_SECRET", VALID_SECRET)
    monkeypatch.setenv("TS_CORS_ORIGINS", "http://a.example,http://b.example")

    settings = Settings(_env_file=None)

    assert settings.cors_origins == ("http://a.example", "http://b.example")


def test_wildcard_cors_origin_is_rejected_from_the_environment_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TS_DATABASE_URL", VALID_DSN)
    monkeypatch.setenv("TS_JWT_SECRET", VALID_SECRET)
    monkeypatch.setenv("TS_CORS_ORIGINS", "*")

    with pytest.raises(PydanticValidationError, match="must not contain"):
        Settings(_env_file=None)
