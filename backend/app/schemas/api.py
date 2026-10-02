"""API-facing Pydantic contracts.

Kept separate from ``app.normalize.models`` on purpose. The internal model uses
lowercase ``StrEnum`` members (nice to read in Python), while the wire format
uses the uppercase short codes the dashboard and OSCAL tooling expect. The
conversion happens here, in one place, so no endpoint has to remember it.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.normalize import models as internal


class Vendor(StrEnum):
    """Wire representation of a vendor code."""

    CISCO_IOS = "cisco_ios"
    CISCO_NXOS = "cisco_nxos"
    JUNIPER_JUNOS = "juniper_junos"
    FORTINET_FORTIOS = "fortinet_fortios"
    PALOALTO_PANOS = "paloalto_panos"
    UNKNOWN = "unknown"

    @classmethod
    def from_internal(cls, v: internal.Vendor) -> Vendor:
        return cls(v.value)


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_internal(cls, v: internal.Severity) -> Severity:
        return cls(v.value)

    @property
    def rank(self) -> int:
        return internal.SEVERITY_ORDER[internal.Severity(self.value)]


class Framework(StrEnum):
    """Uppercase short codes used by the UI and by OSCAL catalogs."""

    CIS_CISCO_IOS = "CIS_CISCO_IOS"
    CIS_NXOS = "CIS_NXOS"
    CIS_FORTINET = "CIS_FORTINET"
    CIS_PANOS = "CIS_PANOS"
    CIS_JUNOS = "CIS_JUNOS"
    NIST_800_53 = "NIST_800_53"
    NIST_CSF = "NIST_CSF"
    DISA_STIG = "DISA_STIG"
    ISO_27001 = "ISO_27001"
    ISO_27002 = "ISO_27002"

    @classmethod
    def from_internal(cls, v: internal.Framework) -> Framework:
        return _INTERNAL_TO_API[v]


_INTERNAL_TO_API: dict[internal.Framework, Framework] = {
    internal.Framework.CIS_CISCO_IOS: Framework.CIS_CISCO_IOS,
    internal.Framework.CIS_FORTINET: Framework.CIS_FORTINET,
    internal.Framework.CIS_PANOS: Framework.CIS_PANOS,
    internal.Framework.CIS_JUNOS: Framework.CIS_JUNOS,
    internal.Framework.NIST_800_53: Framework.NIST_800_53,
    internal.Framework.NIST_CSF: Framework.NIST_CSF,
    internal.Framework.DISA_STIG: Framework.DISA_STIG,
    internal.Framework.ISO_27001: Framework.ISO_27001,
    internal.Framework.ISO_27002: Framework.ISO_27002,
}


class Detector(StrEnum):
    """Which analysis stage produced a finding. Drives trust weighting."""

    RULE = "rule"
    ML = "ml"
    GRAPH = "graph"
    LLM = "llm"
    HYBRID = "hybrid"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


class RemediationStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    FAILED = "failed"


class CommandMode(StrEnum):
    EXEC = "exec"
    CONFIGURE = "configure"
    EDIT = "edit"
    SET = "set"
    EXIT = "exit"


# --------------------------------------------------------------------------- #
class ControlRef(BaseModel):
    """A cross-reference to a published control (CIS, NIST, STIG, ISO)."""

    model_config = ConfigDict(frozen=True)

    framework: Framework
    control_id: Annotated[str, Field(examples=["CIS-CISCO-1.1.1", "AC-2", "SV-230221r190352"])]
    title: str
    description: str | None = None
    reference_url: str | None = None


class EvidenceLine(BaseModel):
    """One verbatim config line backing a finding."""

    line_no: Annotated[int, Field(ge=0)]
    raw: str


class Finding(BaseModel):
    """A single compliance violation, with proof and an explanation.

    The contract every consumer relies on: an exact control reference, the
    severity, the config lines that prove it, and prose a non-network engineer
    can act on.
    """

    id: str
    analysis_id: str
    device_id: str
    rule_id: str
    title: str
    description: str
    explanation: Annotated[str, Field(description="Plain-language impact statement, no jargon assumed")]
    severity: Severity
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    status: FindingStatus = FindingStatus.OPEN
    category: str
    controls: list[ControlRef] = Field(default_factory=list)
    evidence: list[EvidenceLine] = Field(default_factory=list)
    evidence_precision: Literal["line", "block"] = "line"
    affected_objects: list[str] = Field(default_factory=list)
    remediation_id: str | None = None
    detector: Detector = Detector.RULE
    cvss_score: float | None = None
    created_at: datetime


class RemediationCommand(BaseModel):
    """One ordered step of a vendor-specific fix."""

    order: Annotated[int, Field(ge=0)]
    mode: CommandMode
    command: str
    config_before: str | None = None
    config_after: str | None = None
    description: str
    reversible: bool = True
    requires_confirmation: bool = False


class Remediation(BaseModel):
    id: str
    finding_id: str
    device_id: str
    vendor: Vendor
    status: RemediationStatus = RemediationStatus.PENDING_REVIEW
    title: str
    rationale: str
    risk: Literal["low", "medium", "high"] = "low"
    generator: Literal["hier_config", "template", "llm", "hybrid"] = "template"
    commands: list[RemediationCommand] = Field(default_factory=list)
    diff_summary: str | None = None
    created_at: datetime
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_note: str | None = None
    #: Explicitly False while nothing has been pushed to a device.
    applied_to_device: bool = False


class FrameworkScore(BaseModel):
    framework: Framework
    score: Annotated[float, Field(ge=0.0, le=100.0)]
    passed: int
    failed: int
    not_applicable: int
    total_controls: int
    #: False when too few controls were actually assessed for this framework to
    #: make the score meaningful. The UI must render these differently -- a
    #: 0.00% score derived from two controls is not a 0.00% compliance rate.
    sufficient_evidence: bool = True


class DeviceCompliance(BaseModel):
    device_id: str
    hostname: str | None = None
    vendor: Vendor
    role: str
    overall_score: Annotated[float, Field(ge=0.0, le=100.0)]
    severity_counts: dict[Severity, int] = Field(default_factory=dict)
    framework_scores: list[FrameworkScore] = Field(default_factory=list)
    total_findings: int = 0
    open_findings: int = 0
    last_analyzed_at: datetime | None = None
    evidence_precision: Literal["line", "block"] = "line"
    parser_coverage: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0


class AnalysisSummary(BaseModel):
    analysis_id: str
    device_id: str
    status: Literal["queued", "running", "completed", "failed"]
    vendor: Vendor
    vendor_confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    started_at: datetime
    completed_at: datetime | None = None
    overall_score: Annotated[float, Field(ge=0.0, le=100.0)] | None = None
    framework_scores: list[FrameworkScore] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    remediations: list[Remediation] = Field(default_factory=list)
    total_findings: int = 0
    duration_ms: int | None = None
    parse_warnings: list[str] = Field(default_factory=list)
    evidence_precision: Literal["line", "block"] = "line"
    parser_coverage: Annotated[float, Field(ge=0.0, le=1.0)] = 1.0
    error: str | None = None


class DashboardSummary(BaseModel):
    generated_at: datetime
    total_devices: int
    total_findings: int
    overall_score: Annotated[float, Field(ge=0.0, le=100.0)]
    severity_counts: dict[Severity, int] = Field(default_factory=dict)
    framework_scores: list[FrameworkScore] = Field(default_factory=list)
    devices: list[DeviceCompliance] = Field(default_factory=list)
    pending_remediations: int = 0
    critical_delta: int = 0
    top_risky_rules: list[TopRiskyRule] = Field(default_factory=list)


class TopRiskyRule(BaseModel):
    rule_id: str
    title: str
    count: int
    severity: Severity


class VendorDetection(BaseModel):
    vendor: Vendor
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    rule_pack: str | None = None
    candidates: list[VendorCandidate] = Field(default_factory=list)
    evidence_precision: Literal["line", "block"] = "line"


class VendorCandidate(BaseModel):
    adapter: str
    score: Annotated[float, Field(ge=0.0, le=1.0)]


class Paged(BaseModel):
    items: list[Any]
    total: int
    limit: int
    offset: int


DashboardSummary.model_rebuild()
VendorDetection.model_rebuild()
