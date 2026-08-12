"""Chunking result payloads under the 10 MB protocol cap."""

from __future__ import annotations

import pytest
from conftest import make_host, make_scan

from threatsculpt_agent.errors import SubmissionTooLargeError
from threatsculpt_agent.models import HostObservation, PortObservation
from threatsculpt_agent.submission import build_submissions, measure

CAP = 10 * 1024 * 1024


def _payload_size(submission) -> int:  # type: ignore[no-untyped-def]
    return len(submission.model_dump_json().encode())


def test_a_small_scan_is_one_chunk() -> None:
    scan = make_scan(tuple(make_host(f"10.0.4.{n}") for n in range(1, 5)))
    chunks = build_submissions(scan, max_bytes=CAP)

    assert len(chunks) == 1
    assert chunks[0].chunk_index == 0
    assert chunks[0].chunk_count == 1
    assert len(chunks[0].hosts) == 4


def test_an_empty_scan_still_submits_one_chunk() -> None:
    """The server needs to hear that a job found nothing, not hear nothing at all."""
    chunks = build_submissions(make_scan(()), max_bytes=CAP)

    assert len(chunks) == 1
    assert chunks[0].hosts == ()


def test_a_large_scan_is_split_and_every_chunk_fits() -> None:
    scan = make_scan(tuple(make_host(f"10.0.{n // 250}.{n % 250}", port_count=20) for n in range(500)))
    chunks = build_submissions(scan, max_bytes=64 * 1024)

    assert len(chunks) > 1
    assert all(_payload_size(chunk) <= 64 * 1024 for chunk in chunks)


def test_every_host_appears_exactly_once_across_chunks() -> None:
    hosts = tuple(make_host(f"10.0.4.{n}", port_count=5) for n in range(1, 60))
    chunks = build_submissions(make_scan(hosts), max_bytes=16 * 1024)

    submitted = [host.ip for chunk in chunks for host in chunk.hosts]
    assert sorted(submitted) == sorted(host.ip for host in hosts)
    assert len(submitted) == len(set(submitted))


def test_chunks_are_indexed_and_counted() -> None:
    hosts = tuple(make_host(f"10.0.4.{n}", port_count=5) for n in range(1, 40))
    chunks = build_submissions(make_scan(hosts), max_bytes=16 * 1024)

    assert [chunk.chunk_index for chunk in chunks] == list(range(len(chunks)))
    assert all(chunk.chunk_count == len(chunks) for chunk in chunks)


def test_scan_metadata_is_repeated_on_every_chunk() -> None:
    scan = make_scan(tuple(make_host(f"10.0.4.{n}", port_count=5) for n in range(1, 40)))
    chunks = build_submissions(scan, max_bytes=16 * 1024)

    assert len(chunks) > 1
    for chunk in chunks:
        assert chunk.nmap_version == scan.nmap_version
        assert chunk.started_at == scan.started_at
        assert chunk.finished_at == scan.finished_at


def test_one_oversized_host_is_split_by_ports() -> None:
    """Idempotency is on (job_id, host_ip), so the same host in two chunks merges."""
    scan = make_scan((make_host("10.0.4.12", port_count=400),))
    chunks = build_submissions(scan, max_bytes=16 * 1024)

    assert len(chunks) > 1
    assert {host.ip for chunk in chunks for host in chunk.hosts} == {"10.0.4.12"}
    assert all(_payload_size(chunk) <= 16 * 1024 for chunk in chunks)


def test_splitting_a_host_preserves_every_port_exactly_once() -> None:
    host = make_host("10.0.4.12", port_count=400)
    chunks = build_submissions(make_scan((host,)), max_bytes=16 * 1024)

    submitted = [port.port for chunk in chunks for h in chunk.hosts for port in h.ports]
    assert sorted(submitted) == sorted(port.port for port in host.ports)


def test_splitting_preserves_host_attributes_on_each_piece() -> None:
    host = make_host("10.0.4.12", port_count=400)
    chunks = build_submissions(make_scan((host,)), max_bytes=16 * 1024)

    for chunk in chunks:
        for piece in chunk.hosts:
            assert piece.ip == host.ip
            assert piece.hostname == host.hostname
            assert piece.state == "up"


def test_the_input_scan_is_never_mutated() -> None:
    host = make_host("10.0.4.12", port_count=400)
    scan = make_scan((host,))
    build_submissions(scan, max_bytes=16 * 1024)

    assert scan.hosts == (host,)
    assert len(scan.hosts[0].ports) == 400


def test_a_host_that_cannot_fit_even_bare_is_an_explicit_failure() -> None:
    host = HostObservation(ip="10.0.4.12", hostname="h" * 4000, ports=())
    with pytest.raises(SubmissionTooLargeError, match="even with no ports"):
        build_submissions(make_scan((host,)), max_bytes=2048)


def test_a_cap_smaller_than_the_envelope_is_rejected_clearly() -> None:
    """No amount of chunking helps if the metadata alone does not fit."""
    with pytest.raises(SubmissionTooLargeError, match="too small"):
        build_submissions(make_scan((make_host("10.0.4.12"),)), max_bytes=512)


def test_measure_accounts_for_the_separator() -> None:
    port = PortObservation(port=443, protocol="tcp", state="open")
    host = HostObservation(ip="10.0.4.12", ports=(port,))
    assert measure(host) == len(host.model_dump_json().encode()) + 1


def test_chunk_sizes_stay_under_the_real_protocol_cap() -> None:
    """The default config value, against a realistically large scan."""
    hosts = tuple(make_host(f"10.{n // 250}.{n % 250}.1", port_count=30) for n in range(600))
    chunks = build_submissions(make_scan(hosts), max_bytes=9 * 1024 * 1024)

    assert all(_payload_size(chunk) < CAP for chunk in chunks)
