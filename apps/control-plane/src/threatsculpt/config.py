"""Application settings.

Every value comes from the environment (or a local ``.env``). Nothing that is a
secret has a default: the process refuses to start rather than run on a
placeholder credential. The v1 service this replaces held live database
credentials in source control; that is the failure mode this module exists to
make impossible.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from threatsculpt.db.dsn import normalise_driver

Environment = Literal["development", "test", "staging", "production"]

MIN_JWT_SECRET_LENGTH = 32


class Settings(BaseSettings):
    """Immutable, validated view of the process environment."""

    model_config = SettingsConfigDict(
        env_prefix="TS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    environment: Environment = "development"
    api_prefix: str = "/api/v1"

    # --- database ---------------------------------------------------------
    database_url: SecretStr
    db_app_role: str = "threatsculpt_app"
    #: Escape hatch for local development only. When true the process will boot
    #: against a SUPERUSER/BYPASSRLS role, which silently disables Row-Level
    #: Security. Deliberately a separate flag rather than something inferred
    #: from `environment`, so switching it on is an explicit, greppable act.
    allow_superuser_db: bool = False
    db_pool_size: Annotated[int, Field(ge=1, le=100)] = 10
    db_max_overflow: Annotated[int, Field(ge=0, le=100)] = 5
    db_echo: bool = False

    # --- auth -------------------------------------------------------------
    jwt_secret: SecretStr
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_ttl_minutes: Annotated[int, Field(ge=1, le=60)] = 15
    refresh_token_ttl_days: Annotated[int, Field(ge=1, le=90)] = 30
    refresh_cookie_name: str = "ts_refresh"
    cookie_secure: bool = True
    cookie_domain: str | None = None
    #: How long a verification token stays usable. Short by design: an unverified
    #: account is inert, and one that is never proved should stop being
    #: verifiable rather than remain claimable indefinitely.
    email_verification_ttl_hours: Annotated[int, Field(ge=1, le=168)] = 24
    #: Delivery mechanism for verification messages. **Neither option delivers
    #: mail** — this branch has no mail infrastructure. ``none`` drops the
    #: message and logs that it did; ``memory`` retains it in-process for
    #: development and tests. Wiring a real provider means one class in
    #: ``auth.delivery`` and one new value here. See SECURITY.md.
    email_delivery: Literal["none", "memory"] = "none"

    # --- http -------------------------------------------------------------
    # NoDecode: pydantic-settings would otherwise try to JSON-parse a tuple
    # field before any validator runs, so the documented
    # `TS_CORS_ORIGINS=http://a,http://b` form would abort start-up. The
    # comma-splitting validator below owns the parsing instead.
    cors_origins: Annotated[tuple[str, ...], NoDecode] = ()
    trusted_proxy_count: Annotated[int, Field(ge=0, le=5)] = 0

    # --- limits -----------------------------------------------------------
    auth_rate_limit_per_minute: Annotated[int, Field(ge=1)] = 10
    general_rate_limit_per_minute: Annotated[int, Field(ge=1)] = 100
    #: Bucket for callers with no usable credential, keyed on source address.
    #: Deliberately separate from — and smaller than — the per-user limit, so an
    #: unauthenticated flood cannot spend a real user's allowance.
    anonymous_rate_limit_per_minute: Annotated[int, Field(ge=1)] = 30
    max_failed_logins: Annotated[int, Field(ge=1)] = 10
    login_lockout_minutes: Annotated[int, Field(ge=1)] = 15

    # --- logging ----------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True

    @field_validator("jwt_secret")
    @classmethod
    def _reject_short_secret(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_JWT_SECRET_LENGTH:
            raise ValueError(f"TS_JWT_SECRET must be at least {MIN_JWT_SECRET_LENGTH} characters")
        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("cors_origins", mode="after")
    @classmethod
    def _reject_wildcard_origin(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if "*" in value:
            raise ValueError(
                "TS_CORS_ORIGINS must not contain '*' — credentialed requests require "
                "an explicit origin allowlist"
            )
        return value

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def sync_database_url(self) -> str:
        """DSN for synchronous consumers."""
        return normalise_driver(self.database_url.get_secret_value())

    def async_database_url(self) -> str:
        """DSN for the asyncio engine.

        psycopg3 serves both the sync and async engines, so one driver token
        covers both.
        """
        return normalise_driver(self.database_url.get_secret_value())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton. Cleared by tests via ``cache_clear()``."""
    return Settings()  # values come from the environment
