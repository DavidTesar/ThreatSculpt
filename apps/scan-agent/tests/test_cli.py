"""CLI surface, with particular attention to what must NOT be on it."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from threatsculpt_agent.cli import build_parser, main
from threatsculpt_agent.daemon import EXIT_FATAL, EXIT_OK
from threatsculpt_agent.logging_setup import SecretRedactingFilter, configure_logging, redact

VALID_CONFIG = """
control_plane_url = "https://cp.threatsculpt.example"
agent_name = "hq-dc-scanner-01"
allowlist = ["10.0.0.0/8"]
"""


def _config(tmp_path: Path, body: str = VALID_CONFIG) -> Path:
    path = tmp_path / "agent.toml"
    path.write_text(body)
    return path


# --- no secrets on the command line ----------------------------------------------------


def test_there_is_no_flag_for_the_api_key_or_token() -> None:
    """argv is world-readable via `ps`; a flag here would be a credential leak by design."""
    options = {
        option
        for action in build_parser()._actions
        for option in action.option_strings
    }
    for forbidden in ("--api-key", "--apikey", "--key", "--token", "--enrollment-token", "--secret"):
        assert forbidden not in options


@pytest.mark.parametrize(
    "argv",
    [
        ["tsa_leaked_key"],
        ["--config=tse_leaked_token"],
        ["--config", "tsa_leaked_key"],
    ],
)
def test_a_credential_pasted_into_argv_refuses_to_start(argv: list[str]) -> None:
    with pytest.raises(SystemExit, match="TS_AGENT_API_KEY"):
        main(argv)


def test_ordinary_arguments_are_accepted() -> None:
    args = build_parser().parse_args(["--config", "/etc/threatsculpt/agent.toml", "--once"])
    assert args.config == Path("/etc/threatsculpt/agent.toml")
    assert args.once


# --- startup validation ------------------------------------------------------------------


def test_check_config_validates_and_exits(tmp_path: Path) -> None:
    assert main(["--config", str(_config(tmp_path)), "--check-config"]) == EXIT_OK


def test_an_empty_allowlist_refuses_to_start(tmp_path: Path) -> None:
    """Every job would be rejected; better to say so than to poll uselessly forever."""
    config = _config(
        tmp_path, 'control_plane_url="https://cp.test"\nagent_name="a"\nallowlist=[]\n'
    )
    assert main(["--config", str(config), "--check-config"]) == EXIT_FATAL


def test_a_bad_config_exits_nonzero_without_a_traceback(tmp_path: Path) -> None:
    config = _config(tmp_path, 'agent_name="missing-url"\n')
    assert main(["--config", str(config), "--check-config"]) == EXIT_FATAL


def test_a_missing_config_file_exits_nonzero(tmp_path: Path) -> None:
    assert main(["--config", str(tmp_path / "absent.toml"), "--check-config"]) == EXIT_FATAL


def test_version_exits_zero() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0


# --- log redaction -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "key=tsa_abc123DEF-456",
        "token tse_one_time_value",
        "Authorization: Bearer tsa_abc123",
        'body {"api_key": "tsa_abc123"}',
    ],
)
def test_credentials_are_scrubbed_from_log_text(text: str) -> None:
    scrubbed = redact(text)
    assert "tsa_abc123" not in scrubbed
    assert "tse_one_time_value" not in scrubbed
    assert "REDACTED" in scrubbed


def test_ordinary_text_is_left_alone() -> None:
    message = "scanning 10.0.4.0/24 with profile service"
    assert redact(message) == message


def test_the_filter_scrubs_messages_and_arguments() -> None:
    record = logging.LogRecord(
        "test", logging.INFO, __file__, 1, "sending %s to %s", ("tsa_secret", "cp"), None
    )
    SecretRedactingFilter().filter(record)

    assert "tsa_secret" not in record.getMessage()


def test_the_filter_scrubs_dict_arguments() -> None:
    # A single mapping arg is passed as a 1-tuple, exactly as logging.Logger does it.
    record = logging.LogRecord(
        "test", logging.INFO, __file__, 1, "headers %(auth)s", ({"auth": "Bearer tsa_secret"},), None
    )
    SecretRedactingFilter().filter(record)

    assert "tsa_secret" not in record.getMessage()


def test_configured_logging_installs_the_redaction_filter(
    caplog: pytest.LogCaptureFixture,
) -> None:
    configure_logging("INFO")
    handler = logging.getLogger().handlers[0]

    assert any(isinstance(f, SecretRedactingFilter) for f in handler.filters)
