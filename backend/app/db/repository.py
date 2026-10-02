"""Domain objects -> SQLAlchemy rows.

Kept separate from :mod:`app.db.models` so the schema can change without the
pipeline knowing, and so every persistence decision sits in one reviewable file.

:meth:`persist_analysis` takes the normalized config *and* the API summary
because neither alone carries what a row needs: the summary is the wire contract
(frontend-facing, deliberately lean), while the config holds the device identity
and the parser metrics that only an auditor cares about.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import (
    AnalysisRow,
    DeviceRow,
    EvidenceRow,
    FindingControlRow,
    FindingRow,
    FrameworkScoreRow,
    RemediationRow,
)
from app.normalize.models import NormalizedConfig
from app.schemas.api import Finding, FrameworkScore, Remediation


@dataclass(frozen=True)
class AnalysisMetrics:
    """Numbers an auditor needs that do not belong on the wire contract."""

    overall_score: float
    assessable_weight: float
    mean_confidence: float
    indeterminate_count: int
    anomaly_scored: bool
    duration_ms: int


def upsert_device(session: Session, cfg: NormalizedConfig) -> DeviceRow:
    """Insert or refresh the device row. Identity comes from the config itself."""
    row = session.get(DeviceRow, cfg.device_id)
    if row is None:
        row = DeviceRow(id=cfg.device_id)
        session.add(row)
    row.vendor = str(cfg.vendor)
    row.hostname = cfg.identity.hostname
    row.model = cfg.identity.model
    row.software_version = cfg.identity.software_version
    row.role = str(cfg.role)
    row.config_sha256 = cfg.raw_config_sha256
    return row


def persist_analysis(
    session: Session,
    *,
    analysis_id: str,
    cfg: NormalizedConfig,
    findings: list[Finding],
    framework_scores: list[FrameworkScore],
    remediations: list[Remediation],
    metrics: AnalysisMetrics,
) -> None:
    """Write one complete scan. The caller owns the transaction."""
    device = upsert_device(session, cfg)

    session.add(
        AnalysisRow(
            id=analysis_id,
            device_id=device.id,
            overall_score=metrics.overall_score,
            assessable_weight=metrics.assessable_weight,
            parser_coverage=1.0 - (cfg.unparsed_line_ratio or 0.0),
            mean_confidence=metrics.mean_confidence,
            indeterminate_count=metrics.indeterminate_count,
            evidence_precision=cfg.evidence_precision,
            vendor_confidence=cfg.detected_vendor_confidence or 0.0,
            parse_warnings="; ".join(cfg.parse_warnings) or None,
            anomaly_scored=metrics.anomaly_scored,
            duration_ms=metrics.duration_ms,
        )
    )

    for score in framework_scores:
        session.add(
            FrameworkScoreRow(
                analysis_id=analysis_id,
                framework=str(score.framework),
                score=score.score,
                passed=score.passed,
                failed=score.failed,
                not_applicable=score.not_applicable,
                total_controls=score.total_controls,
                sufficient_evidence=score.sufficient_evidence,
            )
        )

    for finding in findings:
        session.add(_finding_row(analysis_id, finding))
        for position, line in enumerate(finding.evidence):
            session.add(
                EvidenceRow(
                    finding_id=finding.id,
                    position=position,
                    line_no=line.line_no,
                    raw=line.raw,
                )
            )
        for control in finding.controls:
            session.add(
                FindingControlRow(
                    finding_id=finding.id,
                    framework=str(control.framework),
                    control_id=control.control_id,
                    title=control.title,
                )
            )

    for plan in remediations:
        session.add(
            RemediationRow(
                id=plan.id,
                finding_id=plan.finding_id,
                device_id=plan.device_id,
                vendor=str(plan.vendor),
                title=plan.title,
                rationale=plan.rationale,
                risk=plan.risk,
                generator=plan.generator,
                status=str(plan.status),
                commands=json.dumps([c.model_dump(mode="json") for c in plan.commands]),
                diff_summary=plan.diff_summary,
                applied_to_device=plan.applied_to_device,
            )
        )
        # Link the finding to its plan so the UI can show both together. Set via
        # the mapped attribute rather than a raw UPDATE so the ORM identity map
        # stays truthful for anything read back in the same session.
        finding_row = session.get(FindingRow, plan.finding_id)
        if finding_row is not None:
            finding_row.remediation_id = plan.id


def _finding_row(analysis_id: str, finding: Finding) -> FindingRow:
    return FindingRow(
        id=finding.id,
        analysis_id=analysis_id,
        device_id=finding.device_id,
        rule_id=finding.rule_id,
        title=finding.title,
        description=finding.description,
        explanation=finding.explanation,
        severity=str(finding.severity),
        confidence=finding.confidence,
        status=str(finding.status),
        category=finding.category,
        detector=str(finding.detector),
        evidence_precision=finding.evidence_precision,
        cvss_score=finding.cvss_score,
        affected_objects=json.dumps(finding.affected_objects),
    )


# --------------------------------------------------------------------------- #
# Read helpers
# --------------------------------------------------------------------------- #
def open_finding_counts(session: Session, device_id: str | None = None) -> dict[str, int]:
    """Open findings per severity, optionally for a single device."""
    stmt = select(FindingRow.severity, func.count()).where(FindingRow.status == "open")
    if device_id is not None:
        stmt = stmt.where(FindingRow.device_id == device_id)
    stmt = stmt.group_by(FindingRow.severity)
    counts: dict[str, int] = {}
    for severity, count in session.execute(stmt).tuples().all():
        counts[str(severity)] = int(count)
    return counts


def pending_remediation_count(session: Session) -> int:
    stmt = select(func.count()).select_from(RemediationRow).where(RemediationRow.status == "pending_review")
    return int(session.scalar(stmt) or 0)


def as_dicts(rows: list[Any]) -> list[dict[str, Any]]:
    return [{c.name: getattr(r, c.name) for c in r.__table__.columns} for r in rows]
