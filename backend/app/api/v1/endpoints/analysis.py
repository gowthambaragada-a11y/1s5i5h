"""Analysis endpoints: detect a vendor, scan a config, read past scans.

Reads are served from Postgres. When it is unreachable the history endpoints
return an explicit 503 rather than an empty list, because "no analyses exist" and
"we cannot tell" are different answers and an auditor must not confuse them.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status

from app.api.deps import AnalystDep, PipelineDep, SettingsDep
from app.db.models import AnalysisRow, DeviceRow, FindingRow
from app.db.session import session_scope, unavailable_reason
from app.normalize.registry import get_registry
from app.pipeline.orchestrator import AnalysisError
from app.schemas.api import (
    AnalysisSummary,
    ControlRef,
    Detector,
    EvidenceLine,
    Finding,
    FindingStatus,
    Framework,
    FrameworkScore,
    Severity,
    Vendor,
    VendorCandidate,
    VendorDetection,
)

router = APIRouter(tags=["analysis"])


@router.get("/vendors", response_model=list[VendorDetection])
def list_vendors() -> list[VendorDetection]:
    """Every adapter we support, with the rule pack each one would load."""
    from app.analysis.rule_packs import rules_for_vendor

    out: list[VendorDetection] = []
    for normalizer in get_registry().normalizers:
        vendor = normalizer.vendor
        out.append(
            VendorDetection(
                vendor=Vendor.from_internal(vendor),
                confidence=1.0,
                rule_pack=f"{len(rules_for_vendor(vendor))} rules",
                candidates=[VendorCandidate(adapter=type(normalizer).__name__, score=1.0)],
                evidence_precision=type(normalizer).evidence_precision,
            )
        )
    return out


@router.post("/analyze", response_model=AnalysisSummary, status_code=status.HTTP_201_CREATED)
async def analyze_config(
    pipeline: PipelineDep,
    _user: AnalystDep,
    settings: SettingsDep,
    file: Annotated[UploadFile, File(...)],
) -> AnalysisSummary:
    """Scan one uploaded device configuration."""
    raw = await _read_upload(file, settings)
    try:
        result = pipeline.analyze(raw.decode("utf-8", errors="replace"))
    except AnalysisError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return result.summary


async def _read_upload(file: UploadFile, settings: Any) -> bytes:
    from app.core.security import validate_upload_name

    # Suffix first -- cheap, and it rejects a file before we buffer any of it.
    try:
        validate_upload_name(file.filename or "", settings=settings)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    # Read one byte past the cap so an oversized upload is detected rather than
    # silently truncated into a config that parses as something else.
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"config exceeds {settings.max_upload_bytes} bytes",
        )
    if not data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is empty")
    return data


@router.get("/analyses", response_model=list[AnalysisSummary])
def list_analyses(
    _user: AnalystDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    device_id: str | None = None,
) -> list[AnalysisSummary]:
    with session_scope() as session:
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"analysis history unavailable: {unavailable_reason() or 'postgres unreachable'}",
            )
        query = session.query(AnalysisRow).order_by(AnalysisRow.created_at.desc())
        if device_id:
            query = query.filter(AnalysisRow.device_id == device_id)
        return [_summary_from_row(session, row) for row in query.offset(offset).limit(limit)]


@router.get("/analyses/{analysis_id}", response_model=AnalysisSummary)
def get_analysis(analysis_id: str, _user: AnalystDep) -> AnalysisSummary:
    with session_scope() as session:
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="analysis history unavailable",
            )
        row = session.get(AnalysisRow, analysis_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="analysis not found")
        return _summary_from_row(session, row)


def _summary_from_row(session: Any, row: AnalysisRow) -> AnalysisSummary:
    """Rebuild the wire shape from stored rows.

    History is a convenience, not the system of record for analysis -- it is
    reconstructed here from the relational rows so that the dashboard always sees
    the same schema whether results came from the pipeline or from Postgres.
    """
    device = session.get(DeviceRow, row.device_id)
    findings = session.query(FindingRow).filter(FindingRow.analysis_id == row.id).all()

    summary = AnalysisSummary(
        analysis_id=row.id,
        device_id=row.device_id,
        status="completed",
        vendor=_vendor(device.vendor if device else None),
        vendor_confidence=row.vendor_confidence,
        started_at=row.created_at,
        completed_at=row.created_at,
        overall_score=row.overall_score,
        findings=[_finding_from_row(f) for f in findings],
        framework_scores=[
            FrameworkScore(
                framework=Framework(s.framework),
                score=s.score,
                passed=s.passed,
                failed=s.failed,
                not_applicable=s.not_applicable,
                total_controls=s.total_controls,
                sufficient_evidence=s.sufficient_evidence,
            )
            for s in row.framework_scores
        ],
        total_findings=len(findings),
        duration_ms=row.duration_ms,
        parse_warnings=row.parse_warnings.split("; ") if row.parse_warnings else [],
        evidence_precision=row.evidence_precision,  # type: ignore[arg-type]
        parser_coverage=row.parser_coverage if row.parser_coverage is not None else 1.0,
    )
    return summary


def _finding_from_row(row: FindingRow) -> Finding:
    return Finding(
        id=row.id,
        analysis_id=row.analysis_id,
        device_id=row.device_id,
        rule_id=row.rule_id,
        title=row.title,
        description=row.description,
        explanation=row.explanation,
        severity=Severity(row.severity),
        confidence=row.confidence,
        status=FindingStatus(row.status),
        category=row.category,
        controls=[
            ControlRef(framework=Framework(c.framework), control_id=c.control_id, title=c.title)
            for c in row.controls
        ],
        evidence=[EvidenceLine(line_no=e.line_no, raw=e.raw) for e in row.evidence],
        evidence_precision=row.evidence_precision,  # type: ignore[arg-type]
        detector=Detector(row.detector),
        created_at=row.created_at,
    )


def _vendor(value: str | None) -> Vendor:
    try:
        return Vendor(value) if value else Vendor.UNKNOWN
    except ValueError:
        return Vendor.UNKNOWN


__all__ = ["router"]
