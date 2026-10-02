"""Remediation review endpoints.

The important property of this module is what it *cannot* do: there is no
``apply`` endpoint. A plan can be approved or rejected by a human, and an
approval records who did it and when. Pushing a command to a live device is out
of scope for an assessment tool -- doing it would make every finding here a
liability rather than a report.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.deps import AnalystDep
from app.db.models import RemediationRow
from app.db.session import session_scope, unavailable_reason
from app.schemas.api import Remediation, RemediationCommand, RemediationStatus, Vendor

router = APIRouter(prefix="/remediations", tags=["remediation"])


class ReviewRequest(BaseModel):
    """A human decision on a proposed change."""

    decision: RemediationStatus
    note: str = Field(default="", max_length=2000)


class RemediationDetail(BaseModel):
    plan: Remediation
    finding_id: str
    rule_id: str
    finding_title: str
    severity: str
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_note: str | None = None
    applied_to_device: bool = False

    model_config = {"from_attributes": True}


#: Approving is allowed; "applied" is not a status the API can ever set.
_ALLOWED_TRANSITIONS: dict[RemediationStatus, set[RemediationStatus]] = {
    RemediationStatus.PENDING_REVIEW: {
        RemediationStatus.APPROVED,
        RemediationStatus.REJECTED,
    },
    RemediationStatus.APPROVED: {RemediationStatus.REJECTED},
    RemediationStatus.REJECTED: {RemediationStatus.PENDING_REVIEW},
}


@router.get("", response_model=list[RemediationDetail])
def list_remediations(
    _user: AnalystDep,
    status_filter: Annotated[RemediationStatus | None, Query(alias="status")] = None,
) -> list[RemediationDetail]:
    with session_scope() as session:
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"remediation queue unavailable: {unavailable_reason() or 'postgres unreachable'}",
            )
        query = session.query(RemediationRow).order_by(RemediationRow.created_at.desc())
        if status_filter is not None:
            query = query.filter(RemediationRow.status == str(status_filter))
        return [_detail(row) for row in query]


@router.get("/{remediation_id}", response_model=RemediationDetail)
def get_remediation(remediation_id: str, _user: AnalystDep) -> RemediationDetail:
    with session_scope() as session:
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="remediation queue unavailable",
            )
        row = session.get(RemediationRow, remediation_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="remediation not found")
        return _detail(row)


@router.post("/{remediation_id}/review", response_model=RemediationDetail)
def review_remediation(
    remediation_id: str,
    payload: ReviewRequest,
    user: AnalystDep,
) -> RemediationDetail:
    """Record an approve/reject decision. Never applies anything."""
    if payload.decision is RemediationStatus.APPLIED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="this API cannot mark a change as applied; apply it through your change process",
        )
    with session_scope() as session:
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="remediation queue unavailable",
            )
        row = session.get(RemediationRow, remediation_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="remediation not found")

        current = RemediationStatus(row.status)
        if payload.decision not in _ALLOWED_TRANSITIONS.get(current, set()):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"cannot move a plan from {current} to {payload.decision}",
            )
        row.status = str(payload.decision)
        row.reviewed_by = str(user.get("sub", "unknown"))
        row.reviewed_at = datetime.now(UTC)
        row.review_note = payload.note
        # Belt and braces: no review path may set this, whatever the status.
        row.applied_to_device = False
        row.applied_at = None
        return _detail(row)


def _detail(row: RemediationRow) -> RemediationDetail:
    finding = row.finding
    commands = [RemediationCommand(**c) for c in json.loads(row.commands or "[]")]
    return RemediationDetail(
        plan=Remediation(
            id=row.id,
            finding_id=row.finding_id,
            device_id=row.device_id,
            vendor=_vendor(row.vendor),
            created_at=row.created_at,
            title=row.title,
            rationale=row.rationale,
            risk=row.risk,  # type: ignore[arg-type]
            status=RemediationStatus(row.status),
            commands=commands,
            diff_summary=row.diff_summary,
            generator=row.generator,  # type: ignore[arg-type]
            applied_to_device=row.applied_to_device,
        ),
        finding_id=row.finding_id,
        rule_id=finding.rule_id if finding else "",
        finding_title=finding.title if finding else "",
        severity=finding.severity if finding else "info",
        reviewed_by=row.reviewed_by,
        reviewed_at=row.reviewed_at,
        review_note=row.review_note,
        applied_to_device=row.applied_to_device,
    )


def _vendor(value: str) -> Vendor:
    try:
        return Vendor(value)
    except ValueError:
        return Vendor.UNKNOWN
