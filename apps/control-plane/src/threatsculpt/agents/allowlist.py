"""What the control plane tells an agent it may scan.

Read docs/AGENT-PROTOCOL.md §4 before changing anything here. The list this
module produces is **advisory**: the agent checks every target against its own
locally configured allowlist first, and the server's list may only ever narrow
that. A compromised control plane therefore cannot turn a customer's agent into a
scanner-for-hire, because the half of the check that matters does not run here.

That does not make this list unimportant — it is how an operator's authorisation
decisions reach the fleet without touching config on every host — but it does
mean the failure mode of getting it wrong is "an agent refuses work", not "an
agent scans a third party".

The effective list is the org's **authorized** networks, narrowed further by the
agent's own ``allowlist`` column when one is set. Narrowing only: an entry on an
agent that no authorized network covers is dropped rather than honoured.
"""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.pagination import PaginationParams
from threatsculpt.models.agent import Agent
from threatsculpt.models.inventory import Network
from threatsculpt.scanning.targets import narrow_to
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

#: docs/AGENT-PROTOCOL.md §2 — how often an idle agent polls for work.
DEFAULT_POLL_INTERVAL_SECONDS = 30

#: An allowlist is a payload sent on every heartbeat, so it is bounded like any
#: other collection. An org past this many authorized networks needs per-agent
#: allowlists rather than a larger response.
MAX_ALLOWLIST_ENTRIES = 200


async def authorized_networks(session: AsyncSession, scope: OrgScope) -> tuple[str, ...]:
    """Every CIDR this org has registered *and* marked authorized."""
    repository = ScopedRepository(session, scope, Network)
    page = await repository.list(
        PaginationParams(per_page=MAX_ALLOWLIST_ENTRIES),
        Network.authorized.is_(True),
        order_by=[Network.created_at.asc()],
    )
    if page.total > MAX_ALLOWLIST_ENTRIES:
        # Loud rather than silent: an operator whose newest authorized network is
        # missing from an agent's allowlist would otherwise see only an
        # unexplained refusal on the agent side.
        logger.warning(
            "authorized networks exceed the allowlist cap; agents receive a truncated list",
            extra={"org_id": str(scope.org_id), "total": page.total, "cap": MAX_ALLOWLIST_ENTRIES},
        )
    return tuple(network.cidr for network in page.items)


async def effective_allowlist(
    session: AsyncSession, scope: OrgScope, agent: Agent
) -> tuple[str, ...]:
    """The org's authorized ranges, narrowed by this agent's own restriction."""
    allowed = await authorized_networks(session, scope)
    return narrow_to(allowed, agent.allowlist or ())
