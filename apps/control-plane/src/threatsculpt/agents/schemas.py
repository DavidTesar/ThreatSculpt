"""Request and response models for enrollment, heartbeat, and agent management.

The one rule worth stating twice: ``api_key`` and ``enrollment_token`` appear in
exactly one response model each, on the endpoint that mints them. No list or
detail model carries either, because a credential that can be fetched a second
time is a credential that leaks from a log, a cache, or a screenshot.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import Field, field_validator

from threatsculpt.api.schemas import FromAttributes, StrictModel
from threatsculpt.scanning.targets import parse_network

MAX_ALLOWLIST_IN_REQUEST = 64


class EnrollRequest(StrictModel):
    """docs/AGENT-PROTOCOL.md §1. Unauthenticated — the token is the credential."""

    enrollment_token: Annotated[str, Field(min_length=8, max_length=200)]
    name: Annotated[str, Field(min_length=1, max_length=200)]
    version: Annotated[str | None, Field(max_length=64)] = None
    hostname: Annotated[str | None, Field(max_length=255)] = None


class EnrollResponse(StrictModel):
    """``api_key`` is shown here and never again."""

    agent_id: UUID
    api_key: str
    org_id: UUID
    allowlist: tuple[str, ...]
    poll_interval_seconds: int


class HeartbeatRequest(StrictModel):
    version: Annotated[str | None, Field(max_length=64)] = None
    nmap_version: Annotated[str | None, Field(max_length=64)] = None
    healthy: bool = True


class HeartbeatResponse(StrictModel):
    """How allowlist changes reach the fleet, per §2.

    ``revoked`` is always ``false`` when it is returned at all: a revoked key
    fails authentication and gets the 401 that §6 already tells the agent to
    treat as "wipe the key and exit". The field is kept because the protocol
    declares it and an agent may branch on it.
    """

    allowlist: tuple[str, ...]
    poll_interval_seconds: int
    revoked: bool = False


class AgentOut(FromAttributes):
    """Agent as an operator sees it. No key material, only the display prefix."""

    id: UUID
    name: str
    key_prefix: str
    status: str
    version: str | None
    allowlist: tuple[str, ...]
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime


class EnrollmentTokenCreate(StrictModel):
    """``POST /agents``. Issues a token; the agent row appears when it is used.

    ``allowlist`` is a *note* for the operator's own records at this stage — the
    agent's ranges are set on its row once it enrols. Kept out of this model
    entirely rather than accepted and ignored.
    """

    note: Annotated[str | None, Field(max_length=200)] = None


class EnrollmentTokenOut(StrictModel):
    """Shown once, at creation."""

    enrollment_token: str
    expires_at: datetime


class AgentAllowlistUpdate(StrictModel):
    """Narrow one agent to a subset of the org's authorized networks."""

    allowlist: Annotated[tuple[str, ...], Field(max_length=MAX_ALLOWLIST_IN_REQUEST)]

    @field_validator("allowlist")
    @classmethod
    def _check_entries(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalised: list[str] = []
        for entry in value:
            network = parse_network(entry)
            if network is None:
                raise ValueError(f"not a valid CIDR block: {entry!r}")
            normalised.append(str(network))
        return tuple(normalised)
