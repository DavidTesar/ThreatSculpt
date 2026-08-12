"""Enrollment: one-time token in, permanent key out, idempotent on restart."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
from conftest import API_PREFIX, BASE_URL, make_settings

from threatsculpt_agent.api.client import ControlPlaneClient
from threatsculpt_agent.config import AgentSettings
from threatsculpt_agent.enrollment import ensure_enrolled
from threatsculpt_agent.errors import EnrollmentError
from threatsculpt_agent.keystore import KeyStore

ENROLL_RESPONSE = {
    "agent_id": "11111111-1111-1111-1111-111111111111",
    "api_key": "tsa_permanent_key",
    "org_id": "22222222-2222-2222-2222-222222222222",
    "allowlist": ["10.0.0.0/8"],
    "poll_interval_seconds": 45,
}


@pytest.fixture
async def client() -> ControlPlaneClient:
    async with ControlPlaneClient(BASE_URL) as instance:
        yield instance


def _settings_with_token(tmp_path: Path, token: str = "tse_one_time") -> AgentSettings:
    return make_settings(tmp_path, enrollment_token=token)


@respx.mock
async def test_a_fresh_agent_trades_its_token_for_a_key(
    tmp_path: Path, keystore: KeyStore, client: ControlPlaneClient
) -> None:
    route = respx.post(f"{API_PREFIX}/enroll").mock(
        return_value=httpx.Response(201, json=ENROLL_RESPONSE)
    )
    outcome = await ensure_enrolled(_settings_with_token(tmp_path), client, keystore)

    assert outcome.newly_enrolled
    assert outcome.api_key == "tsa_permanent_key"
    assert outcome.server_allowlist == ("10.0.0.0/8",)
    assert outcome.poll_interval_seconds == 45.0
    body = route.calls.last.request.read().decode()
    assert '"enrollment_token":"tse_one_time"' in body
    assert '"name":"test-agent"' in body


@respx.mock
async def test_the_new_key_is_persisted_at_0600(
    tmp_path: Path, keystore: KeyStore, client: ControlPlaneClient
) -> None:
    respx.post(f"{API_PREFIX}/enroll").mock(
        return_value=httpx.Response(201, json=ENROLL_RESPONSE)
    )
    await ensure_enrolled(_settings_with_token(tmp_path), client, keystore)

    assert keystore.read() == "tsa_permanent_key"
    assert oct(keystore.path.stat().st_mode)[-3:] == "600"


@respx.mock
async def test_a_restart_with_a_stored_key_never_calls_enroll(
    tmp_path: Path, keystore: KeyStore, client: ControlPlaneClient
) -> None:
    """Re-enrolling would burn a second token and create a duplicate agent record."""
    keystore.write("tsa_already_enrolled")
    route = respx.post(f"{API_PREFIX}/enroll").mock(
        return_value=httpx.Response(201, json=ENROLL_RESPONSE)
    )
    outcome = await ensure_enrolled(_settings_with_token(tmp_path), client, keystore)

    assert not route.called
    assert outcome.api_key == "tsa_already_enrolled"
    assert not outcome.newly_enrolled


@respx.mock
async def test_enrollment_is_idempotent_across_repeated_starts(
    tmp_path: Path, keystore: KeyStore, client: ControlPlaneClient
) -> None:
    route = respx.post(f"{API_PREFIX}/enroll").mock(
        return_value=httpx.Response(201, json=ENROLL_RESPONSE)
    )
    settings = _settings_with_token(tmp_path)

    first = await ensure_enrolled(settings, client, keystore)
    second = await ensure_enrolled(settings, client, keystore)
    third = await ensure_enrolled(settings, client, keystore)

    assert route.call_count == 1
    assert first.api_key == second.api_key == third.api_key


async def test_an_environment_key_takes_precedence_and_skips_enrollment(
    tmp_path: Path, keystore: KeyStore, client: ControlPlaneClient
) -> None:
    settings = make_settings(tmp_path, api_key="tsa_from_env")
    outcome = await ensure_enrolled(settings, client, keystore)

    assert outcome.api_key == "tsa_from_env"
    assert not keystore.exists()  # an externally managed key is not copied to disk


async def test_a_token_file_is_used_when_the_environment_is_empty(
    tmp_path: Path, keystore: KeyStore, client: ControlPlaneClient
) -> None:
    token_file = tmp_path / "enrollment.token"
    token_file.write_text("tse_from_file")
    token_file.chmod(0o600)
    settings = make_settings(tmp_path, enrollment_token_file=token_file)

    with respx.mock:
        route = respx.post(f"{API_PREFIX}/enroll").mock(
            return_value=httpx.Response(201, json=ENROLL_RESPONSE)
        )
        await ensure_enrolled(settings, client, keystore)

    assert '"enrollment_token":"tse_from_file"' in route.calls.last.request.read().decode()


async def test_the_default_token_path_inside_state_dir_is_used(
    tmp_path: Path, keystore: KeyStore, client: ControlPlaneClient
) -> None:
    token_file = tmp_path / "enrollment.token"
    token_file.write_text("tse_default_path")
    token_file.chmod(0o600)

    with respx.mock:
        route = respx.post(f"{API_PREFIX}/enroll").mock(
            return_value=httpx.Response(201, json=ENROLL_RESPONSE)
        )
        await ensure_enrolled(make_settings(tmp_path), client, keystore)

    assert '"enrollment_token":"tse_default_path"' in route.calls.last.request.read().decode()


async def test_no_key_and_no_token_is_an_actionable_error(
    tmp_path: Path, keystore: KeyStore, client: ControlPlaneClient
) -> None:
    with pytest.raises(EnrollmentError, match="TS_AGENT_ENROLLMENT_TOKEN"):
        await ensure_enrolled(make_settings(tmp_path), client, keystore)


@respx.mock
@pytest.mark.parametrize("status", [400, 401, 409, 500])
async def test_a_rejected_token_surfaces_as_an_enrollment_error(
    tmp_path: Path, keystore: KeyStore, client: ControlPlaneClient, status: int
) -> None:
    """A used or expired token must fail visibly, not leave the agent half-configured."""
    respx.post(f"{API_PREFIX}/enroll").mock(return_value=httpx.Response(status))

    with pytest.raises(EnrollmentError, match="enrollment failed"):
        await ensure_enrolled(_settings_with_token(tmp_path), client, keystore)

    assert not keystore.exists()


@respx.mock
async def test_the_enrollment_token_is_never_written_to_the_key_file(
    tmp_path: Path, keystore: KeyStore, client: ControlPlaneClient
) -> None:
    respx.post(f"{API_PREFIX}/enroll").mock(
        return_value=httpx.Response(201, json=ENROLL_RESPONSE)
    )
    await ensure_enrolled(_settings_with_token(tmp_path), client, keystore)

    assert "tse_" not in keystore.path.read_text()


@respx.mock
async def test_no_secret_is_logged_during_enrollment(
    tmp_path: Path,
    keystore: KeyStore,
    client: ControlPlaneClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    respx.post(f"{API_PREFIX}/enroll").mock(
        return_value=httpx.Response(201, json=ENROLL_RESPONSE)
    )
    with caplog.at_level("DEBUG"):
        await ensure_enrolled(_settings_with_token(tmp_path), client, keystore)

    logged = caplog.text
    assert "tse_one_time" not in logged
    assert "tsa_permanent_key" not in logged
