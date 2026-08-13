"""Legal finding status transitions.

``PATCH /findings/{id}`` accepts a status and nothing else. The table below is
the whole rule set, so "can an analyst do this" is answerable by reading one
dict rather than by tracing branches through a handler.

Two transitions exist that look odd and are deliberate:

* ``remediated -> open`` — a patched host that regresses is the same finding
  coming back, not a new one. The unique constraint on
  ``(org_id, asset_id, port_id, cve_id)`` means enrichment cannot create a
  second row for it even if we wanted one.
* ``false_positive -> open`` — a false-positive call is a human judgement, and
  humans revise them. Making it terminal would mean a mistaken dismissal
  permanently hides a real vulnerability.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final

from threatsculpt.core.errors import SemanticValidationError
from threatsculpt.models.finding import RESOLVED_STATUSES, FindingStatus

ALLOWED_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    FindingStatus.OPEN.value: frozenset(
        {
            FindingStatus.ACCEPTED_RISK.value,
            FindingStatus.REMEDIATED.value,
            FindingStatus.FALSE_POSITIVE.value,
        }
    ),
    FindingStatus.ACCEPTED_RISK.value: frozenset(
        {
            FindingStatus.OPEN.value,
            FindingStatus.REMEDIATED.value,
            FindingStatus.FALSE_POSITIVE.value,
        }
    ),
    FindingStatus.REMEDIATED.value: frozenset({FindingStatus.OPEN.value}),
    FindingStatus.FALSE_POSITIVE.value: frozenset({FindingStatus.OPEN.value}),
}


def validate_transition(current: str, requested: str) -> None:
    """Raise unless ``current -> requested`` is a transition we allow."""
    if current == requested:
        raise SemanticValidationError(
            f"This finding is already '{current}'.",
            field="status",
            code="status_unchanged",
        )
    permitted = ALLOWED_TRANSITIONS.get(current, frozenset())
    if requested not in permitted:
        raise SemanticValidationError(
            f"A finding cannot move from '{current}' to '{requested}'. "
            f"Permitted from '{current}': {', '.join(sorted(permitted)) or 'none'}.",
            field="status",
            code="invalid_status_transition",
        )


def changes_for(requested: str) -> dict[str, Any]:
    """The column changes a validated transition implies.

    ``resolved_at`` is set when a finding leaves the open set and cleared when it
    returns, so "how long was this open" stays answerable after a reopen.
    """
    now = datetime.now(UTC)
    return {
        "status": requested,
        "resolved_at": now if requested in RESOLVED_STATUSES else None,
    }
