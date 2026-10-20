import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.access import get_engagement_or_404, get_finding_or_404, require_role
from app.audit import log_event
from app.db import get_db
from app.models import Engagement, Finding, User
from app.schemas import EngagementIn, FindingIn, FindingStatusIn
from app.sessions import get_current_user, require_csrf

router = APIRouter(tags=["engagements"])
writers = require_role("tester", "admin")


def eng_out(e: Engagement) -> dict:
    return {
        "id": str(e.id),
        "name": e.name,
        "owner_id": str(e.owner_id),
        "created_at": e.created_at.isoformat(),
    }


def finding_out(f: Finding) -> dict:
    return {
        "id": str(f.id),
        "engagement_id": str(f.engagement_id),
        "title": f.title,
        "severity": f.severity,
        "status": f.status,
        "description": f.description,
        "created_at": f.created_at.isoformat(),
    }


@router.post("/engagements", status_code=201)
def create_engagement(
    body: EngagementIn,
    user: User = Depends(writers),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    eng = Engagement(owner_id=user.id, name=body.name)  # owner comes from the session
    db.add(eng)
    db.commit()
    log_event(db, "engagement_created", user.id, f"engagement={eng.id}")
    return eng_out(eng)


@router.get("/engagements")
def list_engagements(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    query = select(Engagement).order_by(Engagement.created_at)
    if user.role != "admin":
        query = query.where(Engagement.owner_id == user.id)
    return [eng_out(e) for e in db.scalars(query)]


@router.get("/engagements/{engagement_id}")
def get_engagement(
    engagement_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    return eng_out(get_engagement_or_404(db, user, engagement_id))


@router.delete("/engagements/{engagement_id}", status_code=204)
def delete_engagement(
    engagement_id: uuid.UUID,
    user: User = Depends(writers),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    eng = get_engagement_or_404(db, user, engagement_id)
    eng_id = eng.id
    db.delete(eng)
    db.commit()
    log_event(db, "engagement_deleted", user.id, f"engagement={eng_id}")


@router.post("/engagements/{engagement_id}/findings", status_code=201)
def create_finding(
    engagement_id: uuid.UUID,
    body: FindingIn,
    user: User = Depends(writers),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    eng = get_engagement_or_404(db, user, engagement_id)
    finding = Finding(
        engagement_id=eng.id,
        title=body.title,
        severity=body.severity,
        description=body.description,
    )
    db.add(finding)
    db.commit()
    log_event(db, "finding_created", user.id, f"finding={finding.id} engagement={eng.id}")
    return finding_out(finding)


@router.get("/engagements/{engagement_id}/findings")
def list_findings(
    engagement_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    eng = get_engagement_or_404(db, user, engagement_id)
    rows = db.scalars(
        select(Finding).where(Finding.engagement_id == eng.id).order_by(Finding.created_at)
    )
    return [finding_out(f) for f in rows]


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    return finding_out(get_finding_or_404(db, user, finding_id))


@router.patch("/findings/{finding_id}")
def update_finding_status(
    finding_id: uuid.UUID,
    body: FindingStatusIn,
    user: User = Depends(writers),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    finding = get_finding_or_404(db, user, finding_id)
    finding.status = body.status
    db.commit()
    log_event(db, "finding_status_changed", user.id, f"finding={finding.id} status={body.status}")
    return finding_out(finding)


@router.delete("/findings/{finding_id}", status_code=204)
def delete_finding(
    finding_id: uuid.UUID,
    user: User = Depends(writers),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    finding = get_finding_or_404(db, user, finding_id)
    fid = finding.id
    db.delete(finding)
    db.commit()
    log_event(db, "finding_deleted", user.id, f"finding={fid}")
