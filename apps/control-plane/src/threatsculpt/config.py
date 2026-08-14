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
    #: Delivery mechanism for verification messages. **Only ``smtp`` delivers.**
    #: ``none`` drops the message and logs that it did; ``memory`` retains it
    #: in-process for development and tests. The process refuses to start on
    #: either unless the escape below is set: an unverified account cannot log
    #: in, so a deployment that cannot deliver can onboard nobody, and failing at
    #: boot is how that gets noticed. See SECURITY.md.
    email_delivery: Literal["none", "memory", "smtp"] = "none"
    #: Escape hatch for local development and tests only, matching
    #: ``allow_superuser_db``. Deliberately a separate, greppable flag rather
    #: than something inferred from ``environment``, so running without email
    #: delivery is an explicit act. Logged at CRITICAL on every boot.
    allow_undeliverable_email: bool = False

    # --- smtp -------------------------------------------------------------
    # Read only when email_delivery == "smtp"; validated together at boot by
    # auth.smtp_config, which reports every problem at once rather than one
    # deploy at a time. SMTP rather than a vendor SDK so the same settings reach
    # SES, SendGrid, Postmark, Mailgun or a customer's own relay.
    smtp_host: str | None = None
    smtp_port: Annotated[int, Field(ge=1, le=65535)] = 587
    smtp_username: str | None = None
    #: Like every other secret here: no default, ``SecretStr`` so it cannot be
    #: printed by accident, and supplied by the environment or not at all.
    smtp_password: SecretStr | None = None
    #: ``starttls`` (587) or ``implicit`` (465) everywhere real. ``none`` is
    #: accepted only for a loopback relay — see ``auth.smtp_config`` — because
    #: unencrypted SMTP puts the relay password and the verification link, which
    #: is itself a credential, on the wire in the clear.
    smtp_tls: Literal["starttls", "implicit", "none"] = "starttls"
    smtp_timeout_seconds: Annotated[float, Field(gt=0, le=60)] = 10.0
    smtp_from_email: str | None = None
    smtp_from_name: str = "ThreatSculpt"
    #: Prove the relay accepts these credentials at boot rather than at the
    #: first registration. A wrong password refuses the boot; an unreachable
    #: relay logs CRITICAL and starts anyway. See ``auth.smtp.preflight``.
    smtp_verify_on_start: bool = True
    #: Public origin of the dashboard, used to build the verification link.
    #: Required for SMTP delivery; must be https in production, because the link
    #: carries a token that grants control of the account.
    public_base_url: str | None = None

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
