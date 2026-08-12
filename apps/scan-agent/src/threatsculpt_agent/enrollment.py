"""First-start enrollment: trade a one-time token for a permanent API key.

Idempotent by construction. The agent enrolls only when it has no key at all; a restart
with a key on disk never touches the enroll endpoint, so a re-run cannot burn a second
enrollment token or create a duplicate agent record.

Credential sources, in order: TS_AGENT_API_KEY, the 0600 key file, then enrollment. The
enrollment token itself comes from TS_AGENT_ENROLLMENT_TOKEN or a 0600 file — never argv.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from . import AGENT_VERSION
from .api.client import ControlPlaneClient
from .config import AgentSettings
from .errors import ApiError, EnrollmentError
from .keystore import KeyStore, read_secret_file
from .models import EnrollRequest

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class EnrollmentOutcome:
    """The credential the agent will run with, plus anything enrollment told us."""

    api_key: str
    newly_enrolled: bool
    agent_id: str | None = None
    org_id: str | None = None
    server_allowlist: tuple[str, ...] | None = None
    poll_interval_seconds: float | None = None


async def ensure_enrolled(
    settings: AgentSettings, client: ControlPlaneClient, keystore: KeyStore
) -> EnrollmentOutcome:
    """Return a usable API key, enrolling only if there is not one already."""
    existing, source = _existing_key(settings, keystore)
    if existing is not None:
        log.info("using existing agent credential from %s; skipping enrollment", source)
        return EnrollmentOutcome(api_key=existing, newly_enrolled=False)

    token = _enrollment_token(settings)
    if token is None:
        expected = settings.enrollment_token_file or settings.state_dir / "enrollment.token"
        raise EnrollmentError(
            "no API key and no enrollment token. Set TS_AGENT_ENROLLMENT_TOKEN, or write "
            f"the token to {expected} with mode 0600, then restart."
        )

    log.info("no stored credential; enrolling with the control plane as %r", settings.agent_name)
    try:
        response = await client.enroll(
            EnrollRequest(
                enrollment_token=token,
                name=settings.agent_name,
                version=AGENT_VERSION,
                hostname=settings.hostname,
            )
        )
    except ApiError as exc:
        raise EnrollmentError(f"enrollment failed: {exc}") from exc

    keystore.write(response.api_key)
    log.info(
        "enrolled as agent %s in org %s; credential stored at %s (mode 0600)",
        response.agent_id,
        response.org_id,
        keystore.path,
    )
    return EnrollmentOutcome(
        api_key=response.api_key,
        newly_enrolled=True,
        agent_id=response.agent_id,
        org_id=response.org_id,
        server_allowlist=response.allowlist,
        poll_interval_seconds=float(response.poll_interval_seconds),
    )


def _existing_key(settings: AgentSettings, keystore: KeyStore) -> tuple[str | None, str]:
    """Return (key, human-readable source). The key itself is never logged."""
    if settings.api_key is not None:
        value = settings.api_key.get_secret_value().strip()
        if value:
            return value, "the TS_AGENT_API_KEY environment variable"
    stored = keystore.read()
    if stored:
        return stored, str(keystore.path)
    return None, "nowhere"


def _enrollment_token(settings: AgentSettings) -> str | None:
    if settings.enrollment_token is not None:
        value = settings.enrollment_token.get_secret_value().strip()
        if value:
            return value
    path = settings.enrollment_token_file or settings.state_dir / "enrollment.token"
    if path.is_file():
        return read_secret_file(path)
    return None
