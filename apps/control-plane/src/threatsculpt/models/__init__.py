"""All mapped models.

Importing this package registers every mapper, which is what
``tenant_table_names()`` and the Alembic autogenerate target rely on. Import it
(not the individual modules) anywhere the full metadata is needed.
"""

from threatsculpt.db.base import Base
from threatsculpt.models.agent import Agent, AgentStatus
from threatsculpt.models.audit import ActorType, AuditAction, AuditLog
from threatsculpt.models.finding import (
    ExploitMaturity,
    Finding,
    FindingStatus,
    Vulnerability,
)
from threatsculpt.models.inventory import (
    Asset,
    AssetService,
    BusinessService,
    Criticality,
    Exposure,
    Network,
)
from threatsculpt.models.org import Org, OrgPlan, OrgStatus
from threatsculpt.models.scan import (
    MAX_JOB_ATTEMPTS,
    Port,
    ScanJob,
    ScanProfile,
    ScanResult,
    ScanStatus,
)
from threatsculpt.models.token import EnrollmentToken, RefreshToken
from threatsculpt.models.user import ROLE_RANK, Role, User, UserStatus, outranks_or_equals

__all__ = [
    "MAX_JOB_ATTEMPTS",
    "ROLE_RANK",
    "ActorType",
    "Agent",
    "AgentStatus",
    "Asset",
    "AssetService",
    "AuditAction",
    "AuditLog",
    "Base",
    "BusinessService",
    "Criticality",
    "EnrollmentToken",
    "ExploitMaturity",
    "Exposure",
    "Finding",
    "FindingStatus",
    "Network",
    "Org",
    "OrgPlan",
    "OrgStatus",
    "Port",
    "RefreshToken",
    "Role",
    "ScanJob",
    "ScanProfile",
    "ScanResult",
    "ScanStatus",
    "User",
    "UserStatus",
    "Vulnerability",
    "outranks_or_equals",
]
