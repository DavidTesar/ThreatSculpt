"""Configuration loading, precedence, and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from threatsculpt_agent.config import (
    PROTOCOL_MAX_PAYLOAD_BYTES,
    AgentSettings,
    load_settings,
)
from threatsculpt_agent.errors import ConfigError

TOML = """
control_plane_url = "https://cp.threatsculpt.example"
agent_name = "hq-dc-scanner-01"
allowlist = ["10.0.0.0/8", "192.168.0.0/16"]
poll_interval_seconds = 45
log_level = "DEBUG"
"""


def _write_config(tmp_path: Path, body: str = TOML) -> Path:
    path = tmp_path / "agent.toml"
    path.write_text(body)
    return path


def test_a_toml_file_is_loaded(tmp_path: Path) -> None:
    settings = load_settings(_write_config(tmp_path))

    assert settings.agent_name == "hq-dc-scanner-01"
    assert [str(net) for net in settings.allowlist] == ["10.0.0.0/8", "192.168.0.0/16"]
    assert settings.poll_interval_seconds == 45
    assert settings.log_level == "DEBUG"


def test_the_environment_overrides_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TS_AGENT_AGENT_NAME", "from-env")
    monkeypatch.setenv("TS_AGENT_POLL_INTERVAL_SECONDS", "5")

    settings = load_settings(_write_config(tmp_path))

    assert settings.agent_name == "from-env"
    assert settings.poll_interval_seconds == 5


def test_secrets_are_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TS_AGENT_API_KEY", "tsa_from_env")
    settings = AgentSettings(control_plane_url="https://cp.test", agent_name="a")

    assert settings.api_key is not None
    assert settings.api_key.get_secret_value() == "tsa_from_env"


def test_a_secret_never_appears_in_repr_or_str(monkeypatch: pytest.MonkeyPatch) -> None:
    """SecretStr keeps a credential out of an accidental print or traceback."""
    monkeypatch.setenv("TS_AGENT_API_KEY", "tsa_from_env")
    monkeypatch.setenv("TS_AGENT_ENROLLMENT_TOKEN", "tse_from_env")
    settings = AgentSettings(control_plane_url="https://cp.test", agent_name="a")

    assert "tsa_from_env" not in repr(settings)
    assert "tse_from_env" not in str(settings)


def test_allowlist_entries_are_parsed_as_networks_not_strings(tmp_path: Path) -> None:
    from ipaddress import IPv4Network

    settings = load_settings(_write_config(tmp_path))
    assert isinstance(settings.allowlist[0], IPv4Network)


@pytest.mark.parametrize("entry", ["10.0.0.0/33", "not-a-cidr", "10.0.4.12/24"])
def test_a_bad_allowlist_entry_fails_at_load(tmp_path: Path, entry: str) -> None:
    """Fail at startup, not on the first job that would have been mis-validated."""
    config = _write_config(tmp_path, f'control_plane_url="https://c.test"\nagent_name="a"\nallowlist=["{entry}"]\n')
    with pytest.raises(ConfigError):
        load_settings(config)


@pytest.mark.parametrize(
    "url", ["http://cp.example.com", "ftp://cp.example.com", "cp.example.com", ""]
)
def test_a_non_https_control_plane_is_refused(tmp_path: Path, url: str) -> None:
    config = _write_config(tmp_path, f'control_plane_url="{url}"\nagent_name="a"\n')
    with pytest.raises(ConfigError, match="https"):
        load_settings(config)


@pytest.mark.parametrize("url", ["http://localhost:8000", "http://127.0.0.1:8000"])
def test_plain_http_is_allowed_only_for_loopback(tmp_path: Path, url: str) -> None:
    config = _write_config(tmp_path, f'control_plane_url="{url}"\nagent_name="a"\n')
    assert load_settings(config).control_plane_url == url


def test_a_trailing_slash_is_normalised(tmp_path: Path) -> None:
    config = _write_config(tmp_path, 'control_plane_url="https://cp.test/"\nagent_name="a"\n')
    assert load_settings(config).control_plane_url == "https://cp.test"


def test_the_payload_cap_cannot_exceed_the_protocol_limit(tmp_path: Path) -> None:
    config = _write_config(
        tmp_path,
        f'control_plane_url="https://c.test"\nagent_name="a"\n'
        f"max_payload_bytes={PROTOCOL_MAX_PAYLOAD_BYTES + 1}\n",
    )
    with pytest.raises(ConfigError, match="protocol cap"):
        load_settings(config)


def test_an_unknown_config_key_is_reported(tmp_path: Path) -> None:
    """A typo must not silently leave a security setting at its default."""
    config = _write_config(
        tmp_path, 'control_plane_url="https://c.test"\nagent_name="a"\nallow_list=["10.0.0.0/8"]\n'
    )
    with pytest.raises(ConfigError):
        load_settings(config)


def test_a_missing_config_file_is_reported_clearly(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_settings(tmp_path / "nope.toml")


def test_missing_required_fields_are_reported(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_settings(_write_config(tmp_path, 'agent_name="a"\n'))


def test_settings_are_frozen(tmp_path: Path) -> None:
    """The allowlist must not be reassignable at runtime by anything the server sends."""
    from pydantic import ValidationError

    settings = load_settings(_write_config(tmp_path))
    with pytest.raises(ValidationError):
        settings.allowlist = ()


def test_the_key_file_defaults_inside_the_state_directory(tmp_path: Path) -> None:
    settings = AgentSettings(
        control_plane_url="https://cp.test", agent_name="a", state_dir=tmp_path
    )
    assert settings.resolved_api_key_file == tmp_path / "agent.key"


def test_loading_does_not_leak_the_config_path_env_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    monkeypatch.setenv("TS_AGENT_CONFIG_FILE", "/somewhere/else.toml")
    load_settings(_write_config(tmp_path))

    assert os.environ["TS_AGENT_CONFIG_FILE"] == "/somewhere/else.toml"
