"""SQLAlchemy ORM models for NETGUARD-AI.

Design notes
------------
* **Row-per-finding, not JSON blobs.** An auditor filters by severity, vendor and
  control across devices, so those columns have to be real and indexable.
* **Evidence is stored verbatim in a child table.** It is already redacted at
  normalisation time; storing it relationally lets us prove exactly which line
  backed which finding long after the upload is gone.
* **Nothing here executes remediation.** :class:`RemediationRow` records the
  review decision and the commands that *were proposed*; ``applied_to_device`` is
  only ever set by an explicit, separately audited code path.
* **No cascade delete on device.** Deleting a device should be an explicit,
  reversible act. Foreign keys are declared without ``ondelete`` so the database
  refuses the delete and the operator must decide what to do.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for every table in the schema."""


class DeviceRow(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    vendor: Mapped[str] = mapped_column(String(32), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    model: Mapped[str | None] = mapped_column(String(255))
    software_version: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    #: SHA-256 of the uploaded config, so a re-upload can be deduplicated and an
    #: auditor can prove which file produced a finding.
    config_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    analyses: Mapped[list[AnalysisRow]] = relationship(back_populates="device", cascade="all, delete-orphan")
    findings: Mapped[list[FindingRow]] = relationship(back_populates="device", cascade="all, delete-orphan")


class AnalysisRow(Base):
    """One scan of one device. Re-uploading creates a new row, never overwrites."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    overall_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    assessable_weight: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    parser_coverage: Mapped[float | None] = mapped_column(Float)
    mean_confidence: Mapped[float | None] = mapped_column(Float)
    indeterminate_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    evidence_precision: Mapped[str] = mapped_column(String(8), default="line", nullable=False)
    vendor_confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    parse_warnings: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Set when the ML stage ran, false when it was skipped for lack of peers.
    anomaly_scored: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    device: Mapped[DeviceRow] = relationship(back_populates="analyses")
    findings: Mapped[list[FindingRow]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    framework_scores: Mapped[list[FrameworkScoreRow]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_device_severity", "device_id", "severity"),
        Index("ix_findings_rule", "rule_id"),
        Index("ix_findings_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="other", nullable=False)
    detector: Mapped[str] = mapped_column(String(16), default="rule", nullable=False)
    evidence_precision: Mapped[str] = mapped_column(String(8), default="line", nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    affected_objects: Mapped[str | None] = mapped_column(Text)
    #: Denormalised pointer so the UI can join finding -> plan without a second
    #: query. The authoritative link is remediations.finding_id (unique).
    remediation_id: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    analysis: Mapped[AnalysisRow] = relationship(back_populates="findings")
    device: Mapped[DeviceRow] = relationship(back_populates="findings")
    evidence: Mapped[list[EvidenceRow]] = relationship(back_populates="finding", cascade="all, delete-orphan")
    controls: Mapped[list[FindingControlRow]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    remediation: Mapped[RemediationRow | None] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False
    )


class EvidenceRow(Base):
    """One verbatim configuration line backing a finding. Already redacted."""

    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("finding_id", "position", name="uq_evidence_position"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    line_no: Mapped[int] = mapped_column(Integer, nullable=False)
    raw: Mapped[str] = mapped_column(Text, nullable=False)

    finding: Mapped[FindingRow] = relationship(back_populates="evidence")


class FrameworkScoreRow(Base):
    __tablename__ = "framework_scores"
    __table_args__ = (UniqueConstraint("analysis_id", "framework", name="uq_framework_score"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    framework: Mapped[str] = mapped_column(String(32), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    passed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    not_applicable: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_controls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Persisted so the UI can distinguish "0% because we found everything" from
    #: "0% because we only mapped two controls".
    sufficient_evidence: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    analysis: Mapped[AnalysisRow] = relationship(back_populates="framework_scores")


class FindingControlRow(Base):
    """Many-to-many between a finding and the published controls it violates."""

    __tablename__ = "finding_controls"
    __table_args__ = (UniqueConstraint("finding_id", "framework", "control_id", name="uq_finding_control"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    framework: Mapped[str] = mapped_column(String(32), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), default="")

    finding: Mapped[FindingRow] = relationship(back_populates="controls")


class RemediationRow(Base):
    """A *proposed* change awaiting human review.

    There is intentionally no column for "applied by an automated job". Applying
    a change requires an authenticated reviewer, recorded in ``reviewed_by``.
    """

    __tablename__ = "remediations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False, unique=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    #: Denormalised from the device so a queued plan renders without a join.
    vendor: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, default="")
    risk: Mapped[str] = mapped_column(String(8), default="low", nullable=False)
    generator: Mapped[str] = mapped_column(String(16), default="template", nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending_review", nullable=False, index=True)
    commands: Mapped[str] = mapped_column(Text, default="[]")
    diff_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    reviewed_by: Mapped[str | None] = mapped_column(String(255))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_note: Mapped[str | None] = mapped_column(Text)
    applied_to_device: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Set only by an explicit apply path, never by the remediation generator.
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    finding: Mapped[FindingRow] = relationship(back_populates="remediation")


class UserRow(Base):
    """Local operator account. Only hashes are stored, never a password."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    #: Argon2id or scrypt encoded hash -- see app.core.security.hash_password.
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="viewer", nullable=False)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
