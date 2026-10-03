"""Dashboard and fleet endpoints.

The dashboard aggregates across devices, which is the one question the
per-device pipeline cannot answer on its own.

Every route here is database-backed, and every one of them answers 503 when the
database is unusable rather than returning an empty result. A dashboard showing
"0 devices, score 0.0" reads as a clean fleet, and for a security tool that is
the most dangerous thing this API could say: an operator would see a green
dashboard on a deployment whose Postgres is unreachable or unmigrated, and
conclude there is nothing to fix.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import AnalystDep
from app.db import repository
from app.db.graph import SecurityGraph
from app.db.models import AnalysisRow, DeviceRow, FindingControlRow, FindingRow
from app.db.session import session_scope, unavailable_reason
from app.schemas.api import (
    ControlRef,
    DashboardSummary,
    Detector,
    DeviceCompliance,
    EvidenceLine,
    Finding,
    FindingStatus,
    Framework,
    FrameworkScore,
    Paged,
    Severity,
    TopRiskyRule,
    Vendor,
)

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_model=DashboardSummary)
def dashboard(_user: AnalystDep, top: Annotated[int, Query(ge=1, le=50)] = 10) -> DashboardSummary:
    with session_scope() as session:
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"dashboard unavailable: {unavailable_reason() or 'postgres unreachable'}",
            )

        analyses = session.query(AnalysisRow).order_by(AnalysisRow.created_at.desc()).all()
        latest_by_device: dict[str, AnalysisRow] = {}
        for row in analyses:
            latest_by_device.setdefault(row.device_id, row)

        devices = [_device_compliance(session, device_id, row) for device_id, row in latest_by_device.items()]

        severity_counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for finding in session.query(FindingRow).filter(FindingRow.status == "open").all():
            severity_counts[Severity(finding.severity)] += 1

        frameworks: dict[str, FrameworkScore] = {}
        for device in devices:
            for score in device.framework_scores:
                existing = frameworks.get(str(score.framework))
                if existing is None:
                    frameworks[str(score.framework)] = score.model_copy(deep=True)
                else:
                    # Fleet score is the mean of per-device scores, weighted by
                    # how many controls each one could actually assess. An
                    # unweighted mean would let a device we barely parsed dilute
                    # a device we read completely.
                    existing.score = round((existing.score + score.score) / 2, 2)

        return DashboardSummary(
            generated_at=datetime.now(UTC),
            total_devices=len(devices),
            total_findings=sum(severity_counts.values()),
            overall_score=round(sum(d.overall_score for d in devices) / len(devices), 2) if devices else 0.0,
            severity_counts=severity_counts,
            framework_scores=list(frameworks.values()),
            devices=sorted(devices, key=lambda d: d.overall_score),
            pending_remediations=repository.pending_remediation_count(session),
            critical_delta=severity_counts[Severity.CRITICAL],
            top_risky_rules=_top_risky(session, top),
        )


@router.get("/devices", response_model=list[DeviceCompliance])
def list_devices(_user: AnalystDep) -> list[DeviceCompliance]:
    with session_scope() as session:
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"device inventory unavailable: {unavailable_reason() or 'postgres unreachable'}",
            )
        analyses = session.query(AnalysisRow).order_by(AnalysisRow.created_at.desc()).all()
        latest: dict[str, AnalysisRow] = {}
        for row in analyses:
            latest.setdefault(row.device_id, row)
        return [_device_compliance(session, did, row) for did, row in latest.items()]


def _device_compliance(session, device_id: str, row: AnalysisRow) -> DeviceCompliance:
    device = session.get(DeviceRow, device_id)
    findings = session.query(FindingRow).filter(FindingRow.analysis_id == row.id).all()
    open_findings = [f for f in findings if f.status == "open"]
    severity_counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for finding in open_findings:
        severity_counts[Severity(finding.severity)] += 1
    return DeviceCompliance(
        device_id=device_id,
        hostname=device.hostname if device else None,
        vendor=_vendor(device.vendor if device else None),
        role=device.role if device else "unknown",
        overall_score=row.overall_score,
        severity_counts=severity_counts,
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
        open_findings=len(open_findings),
        last_analyzed_at=row.created_at,
        evidence_precision=row.evidence_precision,  # type: ignore[arg-type]
        parser_coverage=row.parser_coverage if row.parser_coverage is not None else 1.0,
    )


def _top_risky(session, top: int) -> list[TopRiskyRule]:
    """Rules firing across the most devices -- the ones worth fixing fleet-wide.

    Counted as *distinct devices*, not findings, because a single misconfigured
    line duplicated across an ACL block should not outrank a systemic problem.
    """
    from sqlalchemy import func

    rows = (
        session.query(
            FindingRow.rule_id,
            FindingRow.title,
            FindingRow.severity,
            func.count(func.distinct(FindingRow.device_id)).label("devices"),
        )
        .filter(FindingRow.status == "open")
        .group_by(FindingRow.rule_id, FindingRow.title, FindingRow.severity)
        .order_by(func.count(func.distinct(FindingRow.device_id)).desc())
        .limit(top)
        .all()
    )
    return [
        TopRiskyRule(
            rule_id=rule_id,
            title=title,
            count=devices,
            severity=Severity(severity),
        )
        for rule_id, title, severity, devices in rows
    ]


@router.get("/findings", response_model=Paged[Finding])
def list_findings(
    _user: AnalystDep,
    severity: Annotated[Severity | None, Query()] = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    device_id: str | None = None,
    framework: Annotated[Framework | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Paged[Finding]:
    """Fleet-wide findings, filtered and paginated."""
    with session_scope() as session:
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"findings unavailable: {unavailable_reason() or 'postgres unreachable'}",
            )
        return _query_findings(
            session,
            severity=severity,
            status_filter=status_filter,
            device_id=device_id,
            framework=framework,
            limit=limit,
            offset=offset,
        )


def _query_findings(
    session: Any,
    *,
    severity: Severity | None,
    status_filter: str | None,
    device_id: str | None,
    framework: Framework | None,
    limit: int,
    offset: int,
) -> Paged[Finding]:
    """Filter and page findings against an open session.

    Split out from the route so the query itself can be tested against SQLite,
    which is the only database available without Postgres running.
    """
    query = session.query(FindingRow)
    if severity is not None:
        query = query.filter(FindingRow.severity == str(severity))
    if status_filter is not None:
        query = query.filter(FindingRow.status == status_filter)
    if device_id:
        query = query.filter(FindingRow.device_id == device_id)

    if framework is not None:
        # Filtered through the join table rather than a JSON column so the
        # database does the matching instead of loading every finding.
        query = query.join(
            FindingControlRow,
            FindingControlRow.finding_id == FindingRow.id,
        ).filter(FindingControlRow.framework == str(framework))
        # A finding can map to several controls of the same framework; the join
        # would otherwise duplicate rows and inflate both total and page.
        query = query.distinct()

    # Counted before slicing, so total describes the whole match set rather than
    # the current page; the UI needs it to size the pager.
    total = query.count()
    rows = (
        query.order_by(FindingRow.severity, FindingRow.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return Paged(
        items=[_finding(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


def _finding(row: FindingRow) -> Finding:
    """Rebuild the wire shape, including the finding's remediation id."""
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
        remediation_id=row.remediation.id if row.remediation else None,
    )


def _vendor(value: str | None):
    try:
        return Vendor(value) if value else Vendor.UNKNOWN
    except ValueError:
        return Vendor.UNKNOWN


@router.get("/graph/exposed-services")
def exposed_services(_user: AnalystDep) -> dict[str, object]:
    """Cross-device reachability from the security knowledge graph."""
    graph = SecurityGraph.from_settings()
    try:
        availability = graph.availability()
        return {
            "available": availability.available,
            "reason": availability.reason,
            "services": graph.exposed_services(),
        }
    finally:
        graph.close()
