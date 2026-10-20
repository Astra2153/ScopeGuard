import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.access import get_target_or_404, require_role
from app.audit import log_event
from app.checks import ScanAborted, run_checks
from app.db import get_db
from app.models import Finding, User
from app.ratelimit import rate_limit
from app.sessions import require_csrf
from app.targets import is_verified_fresh

router = APIRouter(tags=["scans"])
writers = require_role("tester", "admin")


@router.post("/targets/{target_id}/scan", dependencies=[Depends(rate_limit("scan", 3, 60))])
def scan_target(
    target_id: uuid.UUID,
    user: User = Depends(writers),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    target = get_target_or_404(db, user, target_id)
    # Fail closed: no fresh proof of ownership means nothing is sent to the target.
    if not is_verified_fresh(target):
        raise HTTPException(status_code=409, detail="Target is not verified")

    log_event(db, "scan_started", user.id, f"target={target.id}")
    try:
        report = run_checks(target.base_url)
    except ScanAborted as exc:
        log_event(db, "scan_failed", user.id, f"target={target.id} reason={exc.reason}")
        raise HTTPException(status_code=400, detail=f"Scan failed: {exc.reason}")

    created = reopened = unchanged = 0
    for key, check in report.findings.items():
        fingerprint = f"{target.id}:{key}"
        existing = db.scalar(
            select(Finding).where(
                Finding.engagement_id == target.engagement_id, Finding.fingerprint == fingerprint
            )
        )
        if existing is None:
            db.add(Finding(
                engagement_id=target.engagement_id,
                title=check.title[:300],
                severity=check.severity,
                description=f"Target: {target.base_url}\n\n{check.description}",
                source="scanner",
                fingerprint=fingerprint,
            ))
            created += 1
        elif existing.status in ("fixed", "partially_fixed"):
            existing.status = "not_fixed"  # it was marked fixed, but the scan still sees it
            reopened += 1
        else:
            unchanged += 1
    db.commit()
    log_event(
        db, "scan_finished", user.id,
        f"target={target.id} created={created} reopened={reopened} unchanged={unchanged} "
        f"requests={report.requests} incomplete={report.incomplete}",
    )
    return {
        "created": created,
        "reopened": reopened,
        "unchanged": unchanged,
        "requests": report.requests,
        "incomplete": report.incomplete,
    }
