"""Vulnerable-configuration rows for the CVE mirror. **Not tenant-scoped.**

``vulnerabilities.cpes`` is a flat ``text[]`` that answers "which CVEs mention
this product" cheaply via its GIN index. It cannot answer "does version 2.14.1
fall inside the affected window", because a version range is four values and an
array element is one string.

Storing ranges properly is the difference between reporting Log4Shell on every
Log4j installation ever built and reporting it on the ones between 2.0 and
2.15.0. ``vulnerabilities.cpes`` is still populated and still used as the
first-pass filter; this table is what the second pass consults.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from threatsculpt.db.base import Base, TimestampMixin, UuidPkMixin


class VulnerabilityCpeMatch(UuidPkMixin, TimestampMixin, Base):
    """One ``cpeMatch`` entry from an NVD CVE's configuration node."""

    __tablename__ = "vulnerability_cpe_matches"
    __table_args__ = (
        # The matcher's hot path: narrow by software identity, then compare
        # versions in Python where the ordering rules live.
        Index("ix_vulnerability_cpe_matches_vendor_product", "vendor", "product"),
        Index("ix_vulnerability_cpe_matches_cve_id", "cve_id"),
        Index(
            "uq_vulnerability_cpe_matches_cve_id_cpe23",
            "cve_id",
            "cpe23",
            unique=True,
        ),
    )

    cve_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), nullable=False
    )
    #: The criteria as published, in the 2.3 formatted-string binding.
    cpe23: Mapped[str] = mapped_column(String(512), nullable=False)
    #: Denormalised from ``cpe23`` so the identity filter is an index scan
    #: rather than a string parse over every row in the mirror.
    vendor: Mapped[str] = mapped_column(String(255), nullable=False)
    product: Mapped[str] = mapped_column(String(255), nullable=False)
    version_start_including: Mapped[str | None] = mapped_column(String(128))
    version_start_excluding: Mapped[str | None] = mapped_column(String(128))
    version_end_including: Mapped[str | None] = mapped_column(String(128))
    version_end_excluding: Mapped[str | None] = mapped_column(String(128))
    #: NVD publishes non-vulnerable rows too (the platform a product runs on).
    #: Treating those as affected would attach CVEs to operating systems.
    vulnerable: Mapped[bool] = mapped_column(nullable=False, default=True, server_default="true")
