"""Request and response models for scan jobs and result ingest.

Everything an agent submits is validated here before a single value reaches a
service function. The agent is a client like any other: docs/AGENT-PROTOCOL.md §5
says the control plane re-validates what it sends, and validation that lives in
the handler rather than in the schema is validation somebody eventually skips.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import Field, field_validator

from threatsculpt.api.schemas import FromAttributes, StrictModel
from threatsculpt.models.scan import ScanProfile, ScanStatus
from threatsculpt.scanning.targets import parse_address, parse_network

#: Bounds on one submitted batch. Independent of the byte cap: a payload can be
#: under 10 MB and still be an unreasonable number of rows to insert in one
#: transaction.
MAX_HOSTS_PER_BATCH = 4_096
MAX_PORTS_PER_HOST = 1_024
MAX_CPES_PER_PORT = 32

#: docs/AGENT-PROTOCOL.md §3 — one poll returns at most this many jobs.
MAX_CLAIM_CAPACITY = 10

_MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def _require_cidr(value: str) -> str:
    network = parse_network(value)
    if network is None:
        raise ValueError(f"not a valid CIDR block: {value!r}")
    return str(network)


def _require_address(value: str) -> str:
    address = parse_address(value)
    if address is None:
        raise ValueError(f"not a valid IP address: {value!r}")
    return str(address)


# --- scan jobs (dashboard side) --------------------------------------------


class ScanJobCreate(StrictModel):
    """``POST /scans``. A profile name, never nmap flags."""

    target: Annotated[str, Field(min_length=1, max_length=64)]
    profile: ScanProfile
    network_id: UUID | None = None

    @field_validator("target")
    @classmethod
    def _check_target(cls, value: str) -> str:
        return _require_cidr(value)


class ScanJobOut(FromAttributes):
    id: UUID
    network_id: UUID | None
    target: str
    profile: str
    status: str
    agent_id: UUID | None
    lease_expires_at: datetime | None
    attempts: int
    progress_percent: int | None
    requested_by_user_id: UUID | None
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    created_at: datetime
    updated_at: datetime


# --- claiming (agent side) --------------------------------------------------


class ClaimRequest(StrictModel):
    capacity: Annotated[int, Field(ge=1, le=MAX_CLAIM_CAPACITY)] = 1


class ClaimedJob(StrictModel):
    job_id: UUID
    target: str
    profile: str
    lease_expires_at: datetime


class ClaimResponse(StrictModel):
    jobs: tuple[ClaimedJob, ...]


class JobStatusUpdate(StrictModel):
    """§5 progress. ``completed`` is not accepted here — results submission is
    what completes a job, so a job cannot be marked done without its data."""

    status: ScanStatus
    progress_percent: Annotated[int | None, Field(ge=0, le=100)] = None
    detail: Annotated[str | None, Field(max_length=1000)] = None


class JobRejectRequest(StrictModel):
    """§4. The agent refusing a target is expected behaviour, not an error."""

    reason: Annotated[str, Field(min_length=1, max_length=200)]
    detail: Annotated[str | None, Field(max_length=1000)] = None


class JobStateResponse(StrictModel):
    job_id: UUID
    status: str
    attempts: int


# --- result ingest ----------------------------------------------------------


class OsFingerprint(StrictModel):
    family: Annotated[str | None, Field(max_length=64)] = None
    version: Annotated[str | None, Field(max_length=64)] = None
    accuracy: Annotated[int | None, Field(ge=0, le=100)] = None


class PortObservation(StrictModel):
    port: Annotated[int, Field(ge=1, le=65535)]
    protocol: Annotated[str, Field(min_length=1, max_length=16)]
    state: Annotated[str | None, Field(max_length=32)] = None
    service: Annotated[str | None, Field(max_length=128)] = None
    product: Annotated[str | None, Field(max_length=255)] = None
    version: Annotated[str | None, Field(max_length=128)] = None
    cpes: Annotated[tuple[str, ...], Field(max_length=MAX_CPES_PER_PORT)] = ()


class HostObservation(StrictModel):
    ip: Annotated[str, Field(min_length=1, max_length=64)]
    hostname: Annotated[str | None, Field(max_length=255)] = None
    mac: Annotated[str | None, Field(max_length=17)] = None
    state: Annotated[str | None, Field(max_length=32)] = None
    os: OsFingerprint | None = None
    ports: Annotated[tuple[PortObservation, ...], Field(max_length=MAX_PORTS_PER_HOST)] = ()

    @field_validator("ip")
    @classmethod
    def _check_ip(cls, value: str) -> str:
        return _require_address(value)

    @field_validator("mac")
    @classmethod
    def _check_mac(cls, value: str | None) -> str | None:
        """A ``macaddr`` column rejects anything else with a database error.

        Catching it here turns a 500 into a 400 that names the field.
        """
        if value is None:
            return None
        if not _MAC_PATTERN.match(value):
            raise ValueError(f"not a valid MAC address: {value!r}")
        return value


class ResultsSubmission(StrictModel):
    """§5. Observations only — no CVEs, no severity, no risk.

    ``final`` exists because §5 allows one scan to arrive as several batches but
    the job still needs a moment at which it is done. A chunked submitter sends
    ``final: false`` for every batch but the last; the default suits the common
    case of one batch per job.
    """

    started_at: datetime | None = None
    finished_at: datetime | None = None
    nmap_version: Annotated[str | None, Field(max_length=64)] = None
    hosts: Annotated[tuple[HostObservation, ...], Field(max_length=MAX_HOSTS_PER_BATCH)]
    final: bool = True


class RejectedHost(StrictModel):
    ip: str
    reason: str


class ResultsResponse(StrictModel):
    accepted: bool
    hosts_ingested: int
    hosts_rejected: tuple[RejectedHost, ...] = ()
