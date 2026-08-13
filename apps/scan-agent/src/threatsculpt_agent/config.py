"""Agent configuration: TOML file + environment, never command-line secrets.

Precedence: explicit constructor kwargs > environment (TS_AGENT_*) > TOML file.

The API key and the enrollment token are deliberately NOT ordinary config fields that a
CLI flag could populate — a secret in argv is visible to every user on the box via `ps`.
They arrive from a 0600 file or from the environment only.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field, IPvAnyNetwork, SecretStr, field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from .errors import ConfigError

DEFAULT_CONFIG_PATH = Path("/etc/threatsculpt/agent.toml")
CONFIG_PATH_ENV_VAR = "TS_AGENT_CONFIG_FILE"

# The protocol caps a results POST at 4 MB (AGENT-PROTOCOL.md §5). That number is not
# arbitrary on the server side: it is derived from the row caps, because the body cap is
# what lets the control plane refuse an oversized batch *on the stream*, before anything
# is deserialized. A body large enough to be refused by a row cap after parsing costs the
# server ~30x its wire size in transient memory, so the byte cap is the real defence and
# these two numbers have to agree.
#
# Keep the default comfortably under the ceiling: the cap is measured on the encoded body,
# and a chunk that estimates just under it would fail at the boundary on encoding overhead.
PROTOCOL_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_PAYLOAD_BYTES = 3 * 1024 * 1024


class AgentSettings(BaseSettings):
    """Immutable agent configuration."""

    model_config = SettingsConfigDict(
        env_prefix="TS_AGENT_",
        extra="forbid",
        frozen=True,
        case_sensitive=False,
    )

    # --- identity / transport -------------------------------------------------
    control_plane_url: str
    agent_name: str = Field(min_length=1)
    hostname: str = Field(default_factory=lambda: os.uname().nodename)
    verify_tls: bool = True
    request_timeout_seconds: float = Field(default=30.0, gt=0)

    # --- credentials (env or file only) ---------------------------------------
    state_dir: Path = Path("/var/lib/threatsculpt-agent")
    api_key: SecretStr | None = None
    api_key_file: Path | None = None
    enrollment_token: SecretStr | None = None
    enrollment_token_file: Path | None = None

    # --- the local allowlist: the security boundary ----------------------------
    allowlist: tuple[IPvAnyNetwork, ...] = ()

    # --- poll loop -------------------------------------------------------------
    poll_interval_seconds: float = Field(default=30.0, gt=0)
    # Upper bound matches MAX_CLAIM_CAPACITY on the control plane: a larger value
    # is rejected at claim time, so accepting it here would only defer the error
    # to a running agent that never picks up work.
    capacity: int = Field(default=1, ge=1, le=10)
    backoff_base_seconds: float = Field(default=1.0, gt=0)
    backoff_max_seconds: float = Field(default=300.0, gt=0)
    backoff_multiplier: float = Field(default=2.0, gt=1)
    backoff_jitter_ratio: float = Field(default=0.5, ge=0, le=1)
    max_request_attempts: int = Field(default=5, ge=1, le=10)
    shutdown_grace_seconds: float = Field(default=30.0, ge=0)

    # --- nmap ------------------------------------------------------------------
    nmap_path: Path = Path("/usr/bin/nmap")
    nmap_timeout_seconds: float = Field(default=3600.0, gt=0)
    nmap_max_output_bytes: int = Field(default=256 * 1024 * 1024, gt=0)
    include_port_states: tuple[str, ...] = ("open", "open|filtered")

    # --- submission ------------------------------------------------------------
    max_payload_bytes: int = Field(default=DEFAULT_MAX_PAYLOAD_BYTES, gt=1024)

    # --- logging ---------------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("control_plane_url")
    @classmethod
    def _require_https(cls, value: str) -> str:
        trimmed = value.rstrip("/")
        if trimmed.startswith("https://"):
            return trimmed
        # http is allowed only against loopback, so local development works without TLS.
        if trimmed.startswith("http://") and _is_loopback_url(trimmed):
            return trimmed
        raise ValueError("control_plane_url must use https:// (http:// only for localhost)")

    @field_validator("max_payload_bytes")
    @classmethod
    def _respect_protocol_cap(cls, value: int) -> int:
        if value > PROTOCOL_MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"max_payload_bytes exceeds the {PROTOCOL_MAX_PAYLOAD_BYTES}-byte protocol cap"
            )
        return value

    @property
    def resolved_api_key_file(self) -> Path:
        return self.api_key_file or self.state_dir / "agent.key"

    @property
    def allowlist_networks(self) -> tuple[IPvAnyNetwork, ...]:
        return self.allowlist

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        sources: list[PydanticBaseSettingsSource] = [init_settings, env_settings]
        config_path = Path(os.environ.get(CONFIG_PATH_ENV_VAR, DEFAULT_CONFIG_PATH))
        if config_path.is_file():
            sources.append(TomlConfigSettingsSource(settings_cls, toml_file=config_path))
        return tuple(sources)


def _is_loopback_url(url: str) -> bool:
    host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    return host in {"localhost", "127.0.0.1", "::1", "[::1]"}


def load_settings(config_path: Path | None = None, **overrides: object) -> AgentSettings:
    """Load settings, optionally from an explicit TOML path.

    Raises ConfigError (not a pydantic ValidationError) so the CLI can print something a
    sysadmin can act on.
    """
    previous = os.environ.get(CONFIG_PATH_ENV_VAR)
    if config_path is not None:
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
        os.environ[CONFIG_PATH_ENV_VAR] = str(config_path)
    try:
        return AgentSettings(**overrides)  # type: ignore[arg-type]
    except Exception as exc:  # pydantic ValidationError and friends
        raise ConfigError(f"invalid agent configuration: {exc}") from exc
    finally:
        if config_path is not None:
            if previous is None:
                os.environ.pop(CONFIG_PATH_ENV_VAR, None)
            else:
                os.environ[CONFIG_PATH_ENV_VAR] = previous
