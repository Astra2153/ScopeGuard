import hashlib
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.access import NOT_FOUND, can_access, get_engagement_or_404, require_role
from app.audit import log_event
from app.crypto import key_id, public_key_b64, sign_bytes, verify_signature
from app.db import get_db
from app.models import Engagement, Report, User, utcnow
from app.ratelimit import rate_limit
from app.reportgen import build_report
from app.sessions import get_current_user, require_csrf

router = APIRouter(tags=["reports"])
writers = require_role("tester", "admin")


def get_report_or_404(db: DbSession, user: User, report_id: uuid.UUID) -> Report:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    engagement = db.get(Engagement, report.engagement_id)
    if engagement is None or not can_access(user, engagement):
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    return report


def meta(r: Report) -> dict:
    return {
        "id": str(r.id),
        "engagement_id": str(r.engagement_id),
        "created_at": r.created_at.isoformat(),
        "sha256": r.content_sha256,
        "signature": r.signature,
        "key_id": r.key_id,
        "algorithm": "Ed25519",
        "bytes": len(r.content.encode("utf-8")),
    }


# Defined before /reports/{report_id} so the fixed path wins. Public: a public key is not a secret.
@router.get("/reports/public-key")
def report_public_key():
    return {"algorithm": "Ed25519", "public_key": public_key_b64(), "key_id": key_id()}


@router.post(
    "/engagements/{engagement_id}/reports",
    status_code=201,
    dependencies=[Depends(rate_limit("report", 5, 60))],
)
def create_report(
    engagement_id: uuid.UUID,
    user: User = Depends(writers),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    engagement = get_engagement_or_404(db, user, engagement_id)
    report_id = uuid.uuid4()
    now = utcnow()
    content = build_report(db, engagement, user, report_id, now)
    data = content.encode("utf-8")
    signature = sign_bytes(data)  # fails closed if the key is missing: nothing is stored
    report = Report(
        id=report_id,
        engagement_id=engagement.id,
        created_by=user.id,
        created_at=now,
        content=content,
        content_sha256=hashlib.sha256(data).hexdigest(),
        signature=signature,
        key_id=key_id(),
    )
    db.add(report)
    db.commit()
    log_event(db, "report_created", user.id, f"report={report.id} engagement={engagement.id}")
    return meta(report)


@router.get("/engagements/{engagement_id}/reports")
def list_reports(
    engagement_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    engagement = get_engagement_or_404(db, user, engagement_id)
    rows = db.scalars(
        select(Report).where(Report.engagement_id == engagement.id).order_by(Report.created_at.desc())
    )
    return [meta(r) for r in rows]


@router.get("/reports/{report_id}")
def get_report(
    report_id: uuid.UUID, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)
):
    report = get_report_or_404(db, user, report_id)
    return {**meta(report), "content": report.content}


@router.get("/reports/{report_id}/signature")
def get_signature(
    report_id: uuid.UUID, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)
):
    r = get_report_or_404(db, user, report_id)
    return {
        "sha256": r.content_sha256,
        "signature": r.signature,
        "key_id": r.key_id,
        "algorithm": "Ed25519",
    }


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: uuid.UUID, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)
):
    r = get_report_or_404(db, user, report_id)
    log_event(db, "report_downloaded", user.id, f"report={r.id}")
    return Response(
        content=r.content.encode("utf-8"),
        media_type="text/markdown; charset=utf-8",  # never HTML
        headers={
            "Content-Disposition": f'attachment; filename="scopeguard-report-{r.id}.md"',
            "X-Report-Signature": r.signature,
            "X-Report-Key-Id": r.key_id,
        },
    )


@router.get("/reports/{report_id}/verify")
def verify_report(
    report_id: uuid.UUID, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)
):
    r = get_report_or_404(db, user, report_id)
    data = r.content.encode("utf-8")
    sha_ok = hashlib.sha256(data).hexdigest() == r.content_sha256
    sig_ok = verify_signature(data, r.signature)
    return {
        "valid": sha_ok and sig_ok,
        "sha256_matches": sha_ok,
        "signature_valid": sig_ok,
        "signed_with_current_key": r.key_id == key_id(),
    }
