"""Wire models for docs/AGENT-PROTOCOL.md.

All models are frozen: request/response objects are values, never mutated in place.
Responses use extra="ignore" so a control-plane deploy that adds a field does not break
a fleet of older agents. Requests use extra="forbid" so a typo in agent code is caught.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

_REQUEST = ConfigDict(frozen=True, extra="forbid")
_RESPONSE = ConfigDict(frozen=True, extra="ignore")


class EnrollRequest(BaseModel):
    model_config = _REQUEST

    enrollment_token: str
    name: str
    version: str
    hostname: str


class EnrollResponse(BaseModel):
    model_config = _RESPONSE

    agent_id: str
    api_key: str
    org_id: str
    allowlist: tuple[str, ...] = ()
    poll_interval_seconds: int = 30


class HeartbeatRequest(BaseModel):
    model_config = _REQUEST

    version: str
    nmap_version: str
    healthy: bool = True


class HeartbeatResponse(BaseModel):
    model_config = _RESPONSE

    # None means "the server expressed no opinion"; an empty tuple means "nothing".
    allowlist: tuple[str, ...] | None = None
    poll_interval_seconds: int | None = None
    revoked: bool = False


class ClaimRequest(BaseModel):
    model_config = _REQUEST

    capacity: int = Field(ge=1, le=10)


class ClaimedJob(BaseModel):
    model_config = _RESPONSE

    job_id: str
    target: str
    profile: str
    lease_expires_at: datetime | None = None


class ClaimResponse(BaseModel):
    model_config = _RESPONSE

    jobs: tuple[ClaimedJob, ...] = ()


class RejectRequest(BaseModel):
    model_config = _REQUEST

    reason: str
    detail: str


class StatusRequest(BaseModel):
    """§5 progress. Only ``running`` and ``failed`` are reportable — a job is
    completed by submitting its results, never by announcing it."""

    model_config = _REQUEST

    status: str
    progress_percent: int = Field(ge=0, le=100)
    detail: str | None = None


class PortObservation(BaseModel):
    model_config = _REQUEST

    port: int = Field(ge=0, le=65535)
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    cpes: tuple[str, ...] = ()


class OsObservation(BaseModel):
    model_config = _REQUEST

    family: str | None = None
    version: str | None = None
    accuracy: int | None = Field(default=None, ge=0, le=100)


class HostObservation(BaseModel):
    model_config = _REQUEST

    ip: str
    hostname: str | None = None
    mac: str | None = None
    state: str = "up"
    os: OsObservation | None = None
    ports: tuple[PortObservation, ...] = ()


class ResultSubmission(BaseModel):
    """One results POST. Large scans are split into several of these (see submission.py).

    ``final`` is the wire field the control plane uses to decide when a chunked
    submission is done and the job may complete. ``chunk_index``/``chunk_count``
    are local bookkeeping — they drive the idempotency key and progress reporting
    — and are excluded from serialisation, because the ingest schema forbids
    fields it does not define.
    """

    model_config = _REQUEST

    started_at: datetime
    finished_at: datetime
    nmap_version: str
    hosts: tuple[HostObservation, ...]
    final: bool = True
    chunk_index: int = Field(default=0, ge=0, exclude=True)
    chunk_count: int = Field(default=1, ge=1, exclude=True)


class SubmissionAck(BaseModel):
    model_config = _RESPONSE

    accepted: bool = True
    hosts_ingested: int | None = None


class ParsedScan(BaseModel):
    """Everything the XML parser extracted from one nmap run."""

    model_config = _REQUEST

    nmap_version: str
    started_at: datetime
    finished_at: datetime
    hosts: tuple[HostObservation, ...] = ()
    hosts_up: int = 0
    hosts_total: int = 0
