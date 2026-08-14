"""Turning observed services into scored findings.

The pipeline, all of it bounded and none of it per-row:

1. Load one page of the org's ports (optionally narrowed to one scan job or
   asset set).
2. Collect the distinct ``vendor:product`` identities those ports observed, and
   fetch only the CVE criteria matching those identities. This is the indexed
   prefilter — without it the matcher would walk the entire mirror per port.
3. Match, with a confidence, in memory.
4. Load every asset's exposure and business services in one query.
5. Upsert findings on ``(org_id, asset_id, port_id, cve_id)``.

Step 5 is an upsert, not an insert: docs/DATA-MODEL.md is explicit that a
rescan updates ``last_seen_at`` rather than creating a duplicate. A finding an
operator already triaged must not come back as new because the scanner ran
again — that is how a triage queue becomes untrustworthy.

**Paging is a correctness property here, not a performance one.**
``generate_findings`` covers one page; ``generate_all_findings`` walks every
page and is what callers should use. The page is a keyset walk ordered by port
id, resuming strictly after the last id of the previous page, so every port is
enriched exactly once however many pages it takes.

This used to be a bare ``LIMIT 5000`` with no ``ORDER BY`` and a comment saying
the caller paged. No caller did, and without an ordering there was no page to be
the second one: a ``vulnerability`` profile is ``-p-``, so a sweep of a /24 with
twenty open ports a host is 5,080 ports, and *which* 5,000 of them became
findings was whatever the planner happened to return. Eighty ports were
silently unenriched, and a different eighty on the next run.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import func, select, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.enrichment.cpe import parse_cpe
from threatsculpt.enrichment.matching import CpeCriteria, Match, ObservedSoftware, match_all
from threatsculpt.enrichment.scoring_service import AssetContext, load_asset_contexts, score_for
from threatsculpt.enrichment.versions import VersionRange
from threatsculpt.models.cpe_match import VulnerabilityCpeMatch
from threatsculpt.models.finding import Finding, FindingStatus, Vulnerability
from threatsculpt.models.scan import Port
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

#: Ports loaded, matched and upserted in one page. Sized so a page is one
#: reasonable statement rather than to bound the work: ``generate_all_findings``
#: takes as many pages as the estate needs.
PORTS_PER_PAGE: Final = 5000

#: Hard ceiling on a caller-supplied page size. A page is held in memory and
#: becomes one INSERT, so an unbounded value would move the truncation problem
#: this module just fixed into the caller.
MAX_PORTS_PER_PAGE: Final = 20000

#: Upper bound on criteria rows loaded for one page's identity set. A vendor with
#: a very large CVE history could otherwise pull an unbounded result set.
MAX_CRITERIA_PER_RUN: Final = 20000

#: Findings written per INSERT. See ``_batched`` for why this is not optional.
FINDINGS_PER_STATEMENT: Final = 500


@dataclass(frozen=True, slots=True)
class EnrichmentReport:
    """What one page — or, merged, a whole run — did.

    Frozen: pages combine with ``merge`` rather than accumulating into a mutable
    tally, the same shape ``scanning.sweeper.SweepOutcome`` uses.
    """

    ports_examined: int = 0
    findings_written: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    pages: int = 0
    #: Highest port id this page covered, and so the cursor the next page
    #: resumes strictly after. ``None`` means the page was empty.
    last_port_id: UUID | None = None

    def merge(self, other: EnrichmentReport) -> EnrichmentReport:
        return EnrichmentReport(
            ports_examined=self.ports_examined + other.ports_examined,
            findings_written=self.findings_written + other.findings_written,
            high_confidence=self.high_confidence + other.high_confidence,
            medium_confidence=self.medium_confidence + other.medium_confidence,
            low_confidence=self.low_confidence + other.low_confidence,
            pages=self.pages + other.pages,
            last_port_id=other.last_port_id or self.last_port_id,
        )


@dataclass(frozen=True, slots=True)
class _PortObservation:
    port_id: UUID
    asset_id: UUID
    scan_job_id: UUID | None
    observed: ObservedSoftware


async def generate_all_findings(
    session: AsyncSession,
    scope: OrgScope,
    *,
    scan_job_id: UUID | None = None,
    asset_ids: Sequence[UUID] | None = None,
    page_size: int = PORTS_PER_PAGE,
) -> EnrichmentReport:
    """Every matching port, however many pages that takes.

    This is what a caller wants; ``generate_findings`` is one page of it. The
    walk terminates because each page resumes strictly after the previous
    page's highest port id, so the cursor advances or the page was the last one.
    """
    total = EnrichmentReport()
    cursor: UUID | None = None
    while True:
        page = await generate_findings(
            session,
            scope,
            scan_job_id=scan_job_id,
            asset_ids=asset_ids,
            after_port_id=cursor,
            page_size=page_size,
        )
        total = total.merge(page)
        # A short page is the last page. ``last_port_id is None`` means the page
        # was empty, which is also the end — and is checked rather than assumed,
        # because a cursor that did not move would loop forever.
        if page.ports_examined < page_size or page.last_port_id is None:
            return total
        cursor = page.last_port_id


async def generate_findings(
    session: AsyncSession,
    scope: OrgScope,
    *,
    scan_job_id: UUID | None = None,
    asset_ids: Sequence[UUID] | None = None,
    after_port_id: UUID | None = None,
    page_size: int = PORTS_PER_PAGE,
) -> EnrichmentReport:
    """Match one page of this org's observed services and upsert findings.

    Ports are walked in ``id`` order starting strictly after ``after_port_id``.
    Callers that want the whole estate should use ``generate_all_findings``.
    """
    if not 1 <= page_size <= MAX_PORTS_PER_PAGE:
        raise ValueError(f"page_size must be between 1 and {MAX_PORTS_PER_PAGE}, got {page_size}")

    observations = await _load_observations(
        session, scope, scan_job_id, asset_ids, after_port_id, page_size
    )
    if not observations:
        return EnrichmentReport(pages=1)

    # The cursor belongs to the page, not to what matched: a page in which
    # nothing matched still has to advance, or the walk repeats it forever.
    cursor = observations[-1].port_id

    criteria = await _load_criteria(session, _identities(observations))
    if not criteria:
        return EnrichmentReport(ports_examined=len(observations), pages=1, last_port_id=cursor)

    contexts = await load_asset_contexts(
        session, scope, tuple({item.asset_id for item in observations})
    )
    rows = _build_rows(observations, criteria, contexts)
    written = await _upsert_findings(session, scope, rows)

    report = EnrichmentReport(
        ports_examined=len(observations),
        findings_written=written,
        high_confidence=sum(1 for row in rows if row["match_confidence"] == "high"),
        medium_confidence=sum(1 for row in rows if row["match_confidence"] == "medium"),
        low_confidence=sum(1 for row in rows if row["match_confidence"] == "low"),
        pages=1,
        last_port_id=cursor,
    )
    logger.info(
        "enrichment page complete",
        extra={
            "org_id": str(scope.org_id),
            "ports_examined": report.ports_examined,
            "findings_written": report.findings_written,
            "high_confidence": report.high_confidence,
            "medium_confidence": report.medium_confidence,
            "low_confidence": report.low_confidence,
        },
    )
    return report


async def _load_observations(
    session: AsyncSession,
    scope: OrgScope,
    scan_job_id: UUID | None,
    asset_ids: Sequence[UUID] | None,
    after_port_id: UUID | None,
    page_size: int,
) -> tuple[_PortObservation, ...]:
    from threatsculpt.models.scan import ScanResult

    statement = (
        select(Port.id, Port.asset_id, ScanResult.scan_job_id, Port.cpe, Port.product, Port.version)
        .select_from(Port)
        .join(
            ScanResult,
            (ScanResult.id == Port.scan_result_id) & (ScanResult.org_id == scope.org_id),
        )
        .where(Port.org_id == scope.org_id)
        # The ordering is what makes the page a page. Without it the LIMIT
        # returns whichever rows the planner reached first, so a second page
        # would overlap the first and neither would cover the estate.
        .order_by(Port.id.asc())
        .limit(page_size)
    )
    if after_port_id is not None:
        statement = statement.where(Port.id > after_port_id)
    if scan_job_id is not None:
        statement = statement.where(ScanResult.scan_job_id == scan_job_id)
    if asset_ids is not None:
        if not asset_ids:
            return ()
        statement = statement.where(Port.asset_id.in_(tuple(asset_ids)))

    rows = (await execute_scoped(session, scope, statement)).all()
    return tuple(
        _PortObservation(
            port_id=row.id,
            asset_id=row.asset_id,
            scan_job_id=row.scan_job_id,
            observed=ObservedSoftware(
                cpes=tuple(row.cpe or ()), product=row.product, version=row.version
            ),
        )
        for row in rows
    )


def _identities(observations: Sequence[_PortObservation]) -> tuple[tuple[str, str], ...]:
    """Distinct ``(vendor, product)`` pairs the scan actually saw."""
    pairs: set[tuple[str, str]] = set()
    for item in observations:
        for cpe in item.observed.parsed_cpes():
            if cpe.is_specific_enough_to_match:
                pairs.add((cpe.vendor, cpe.product))
    return tuple(sorted(pairs))


async def _load_criteria(
    session: AsyncSession, identities: tuple[tuple[str, str], ...]
) -> dict[tuple[str, str], tuple[CpeCriteria, ...]]:
    """Fetch criteria for the observed identities only. Global table, plain read."""
    if not identities:
        return {}
    statement = (
        select(VulnerabilityCpeMatch)
        .where(
            tuple_(VulnerabilityCpeMatch.vendor, VulnerabilityCpeMatch.product).in_(identities),
            VulnerabilityCpeMatch.vulnerable.is_(True),
        )
        .limit(MAX_CRITERIA_PER_RUN)
    )
    grouped: dict[tuple[str, str], list[CpeCriteria]] = {}
    for row in (await session.execute(statement)).scalars().all():
        parsed = parse_cpe(row.cpe23)
        if parsed is None:
            continue
        grouped.setdefault((row.vendor, row.product), []).append(
            CpeCriteria(
                cve_id=row.cve_id,
                cpe=parsed,
                version_range=VersionRange(
                    start_including=row.version_start_including,
                    start_excluding=row.version_start_excluding,
                    end_including=row.version_end_including,
                    end_excluding=row.version_end_excluding,
                ),
                vulnerable=row.vulnerable,
            )
        )
    return {key: tuple(value) for key, value in grouped.items()}


def _build_rows(
    observations: Sequence[_PortObservation],
    criteria: dict[tuple[str, str], tuple[CpeCriteria, ...]],
    contexts: dict[UUID, AssetContext],
) -> list[dict[str, Any]]:
    now = datetime.now(UTC)
    rows: dict[tuple[UUID, UUID, str], dict[str, Any]] = {}
    for observation in observations:
        candidates = _candidates_for(observation, criteria)
        if not candidates:
            continue
        for match in match_all(observation.observed, candidates):
            key = (observation.asset_id, observation.port_id, match.cve_id)
            rows[key] = _row_for(observation, match, contexts.get(observation.asset_id), now)
    return list(rows.values())


def _candidates_for(
    observation: _PortObservation, criteria: dict[tuple[str, str], tuple[CpeCriteria, ...]]
) -> tuple[CpeCriteria, ...]:
    collected: list[CpeCriteria] = []
    for cpe in observation.observed.parsed_cpes():
        collected.extend(criteria.get((cpe.vendor, cpe.product), ()))
    return tuple(collected)


def _row_for(
    observation: _PortObservation, match: Match, context: AssetContext | None, now: datetime
) -> dict[str, Any]:
    return {
        "asset_id": observation.asset_id,
        "port_id": observation.port_id,
        "scan_job_id": observation.scan_job_id,
        "cve_id": match.cve_id,
        "match_confidence": match.confidence.value,
        "match_method": match.method.value,
        "match_rationale": match.rationale[:1000],
        "first_seen_at": now,
        "last_seen_at": now,
        "_context": context,
    }


async def _upsert_findings(
    session: AsyncSession, scope: OrgScope, rows: list[dict[str, Any]]
) -> int:
    """Insert or refresh findings, scoring each against the current mirror."""
    if not rows:
        return 0

    scores = await _scores_for(session, rows)
    payload = [
        {
            **{key: value for key, value in row.items() if key != "_context"},
            "org_id": scope.org_id,
            "status": FindingStatus.OPEN.value,
            "business_risk_score": scores[row["cve_id"]][row["asset_id"]].score,
            "score_factors": scores[row["cve_id"]][row["asset_id"]].score_factors(),
        }
        for row in rows
    ]
    for batch in _batched(payload):
        await _upsert_batch(session, scope, batch)
    return len(payload)


def _batched(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Split a page's findings into statement-sized batches.

    Not cosmetic. Every row here binds thirteen parameters and the extended
    query protocol carries at most 65,535 in one statement, so a single INSERT
    tops out around 5,000 findings — and a page produces one row per *match*,
    not per port, so a page of ports each matching three CVEs reaches that with
    ports to spare. Unbatched, the failure is a protocol error from psycopg on
    exactly the large estates this pipeline exists to serve.
    """
    return [
        rows[index : index + FINDINGS_PER_STATEMENT]
        for index in range(0, len(rows), FINDINGS_PER_STATEMENT)
    ]


async def _upsert_batch(
    session: AsyncSession, scope: OrgScope, payload: list[dict[str, Any]]
) -> None:
    statement = pg_insert(Finding).values(payload)
    await execute_scoped(
        session,
        scope,
        statement.on_conflict_do_update(
            index_elements=["org_id", "asset_id", "port_id", "cve_id"],
            set_={
                # A rescan refreshes what it observed and re-scores. It must not
                # touch `status` or `first_seen_at`: the operator owns the first
                # and history owns the second.
                "last_seen_at": statement.excluded.last_seen_at,
                "business_risk_score": statement.excluded.business_risk_score,
                "score_factors": statement.excluded.score_factors,
                "match_confidence": statement.excluded.match_confidence,
                "match_method": statement.excluded.match_method,
                "match_rationale": statement.excluded.match_rationale,
                "scan_job_id": statement.excluded.scan_job_id,
            },
        ),
    )


async def _scores_for(
    session: AsyncSession, rows: list[dict[str, Any]]
) -> dict[str, dict[UUID, Any]]:
    """Score every (cve, asset) pair the batch needs, with one mirror read."""
    cve_ids = tuple({row["cve_id"] for row in rows})
    result = await session.execute(
        select(
            Vulnerability.cve_id,
            Vulnerability.cvss_base,
            Vulnerability.exploit_maturity,
            Vulnerability.kev_listed,
        ).where(Vulnerability.cve_id.in_(cve_ids))
    )
    mirror = {row.cve_id: row for row in result.all()}

    scores: dict[str, dict[UUID, Any]] = {}
    for row in rows:
        entry = mirror.get(row["cve_id"])
        bucket = scores.setdefault(row["cve_id"], {})
        if row["asset_id"] in bucket:
            continue
        bucket[row["asset_id"]] = score_for(
            cvss_base=entry.cvss_base if entry else None,
            exploit_maturity=entry.exploit_maturity if entry else "none",
            kev_listed=bool(entry.kev_listed) if entry else False,
            context=row["_context"],
        )
    return scores


async def count_findings(session: AsyncSession, scope: OrgScope) -> int:
    statement = select(func.count()).select_from(Finding).where(Finding.org_id == scope.org_id)
    return int((await execute_scoped(session, scope, statement)).scalar_one())
