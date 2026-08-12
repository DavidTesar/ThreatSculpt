"""Split a parsed scan into result payloads that fit under the protocol's 10 MB cap.

Chunks are packed by measured serialised size, not by a guessed host count: one host with
65535 open ports is larger than a thousand hosts with two. A host that is too large on its
own has its ports split across several chunks — the ingest endpoint is idempotent on
(job_id, host_ip), so the same host arriving twice merges rather than duplicating.

Chunking is pure: it returns new ResultSubmission values and never mutates the parse.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .errors import SubmissionTooLargeError
from .models import HostObservation, ParsedScan, PortObservation, ResultSubmission

log = logging.getLogger(__name__)

# JSON separators, the "hosts": [] brackets, and a little slack for server-side framing.
_ENVELOPE_SLACK_BYTES = 512


@dataclass(frozen=True, slots=True)
class _Budget:
    """How many bytes of host payload fit in one chunk."""

    per_chunk: int

    @classmethod
    def compute(cls, scan: ParsedScan, max_bytes: int) -> _Budget:
        empty = scan_envelope(scan)
        overhead = len(empty.model_dump_json().encode()) + _ENVELOPE_SLACK_BYTES
        per_chunk = max_bytes - overhead
        if per_chunk <= 0:
            raise SubmissionTooLargeError(
                f"max_payload_bytes={max_bytes} is too small for the submission envelope "
                f"({overhead} bytes)"
            )
        return cls(per_chunk=per_chunk)


def scan_envelope(scan: ParsedScan) -> ResultSubmission:
    """An empty submission carrying the scan's metadata."""
    return ResultSubmission(
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        nmap_version=scan.nmap_version,
        hosts=(),
    )


def measure(host: HostObservation) -> int:
    """Serialised size of one host, plus its comma separator."""
    return len(host.model_dump_json().encode()) + 1


def build_submissions(scan: ParsedScan, *, max_bytes: int) -> tuple[ResultSubmission, ...]:
    """Return every chunk needed to submit ``scan``, in order, with chunk_index set."""
    budget = _Budget.compute(scan, max_bytes)
    groups = _pack(_fit_hosts(scan.hosts, budget.per_chunk), budget.per_chunk)
    if not groups:
        groups = [()]

    envelope = scan_envelope(scan)
    return tuple(
        envelope.model_copy(
            update={"hosts": group, "chunk_index": index, "chunk_count": len(groups)}
        )
        for index, group in enumerate(groups)
    )


def _fit_hosts(
    hosts: tuple[HostObservation, ...], per_chunk: int
) -> list[tuple[HostObservation, int]]:
    """Yield (host, size) pairs, splitting any host that cannot fit in one chunk."""
    fitted: list[tuple[HostObservation, int]] = []
    for host in hosts:
        size = measure(host)
        if size <= per_chunk:
            fitted.append((host, size))
            continue
        log.warning(
            "host %s serialises to %d bytes, over the %d-byte chunk budget; "
            "splitting its ports across chunks",
            host.ip,
            size,
            per_chunk,
        )
        fitted.extend((part, measure(part)) for part in _split_host(host, per_chunk))
    return fitted


def _split_host(host: HostObservation, per_chunk: int) -> list[HostObservation]:
    """Split one host into port-slices that each fit the budget."""
    bare = host.model_copy(update={"ports": ()})
    bare_size = measure(bare)
    if bare_size > per_chunk:
        raise SubmissionTooLargeError(
            f"host {host.ip} does not fit in a {per_chunk}-byte chunk even with no ports"
        )

    parts: list[HostObservation] = []
    current: list[PortObservation] = []
    used = bare_size
    for port in host.ports:
        port_size = len(port.model_dump_json().encode()) + 1
        if current and used + port_size > per_chunk:
            parts.append(bare.model_copy(update={"ports": tuple(current)}))
            current, used = [], bare_size
        current.append(port)
        used += port_size
    parts.append(bare.model_copy(update={"ports": tuple(current)}))
    return parts


def _pack(
    sized_hosts: list[tuple[HostObservation, int]], per_chunk: int
) -> list[tuple[HostObservation, ...]]:
    """Greedy first-fit packing, preserving host order for predictable submissions."""
    groups: list[tuple[HostObservation, ...]] = []
    current: list[HostObservation] = []
    used = 0
    for host, size in sized_hosts:
        if current and used + size > per_chunk:
            groups.append(tuple(current))
            current, used = [], 0
        current.append(host)
        used += size
    if current:
        groups.append(tuple(current))
    return groups
