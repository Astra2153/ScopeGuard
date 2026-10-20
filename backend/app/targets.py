import uuid
from datetime import timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.access import get_engagement_or_404, get_target_or_404, require_role
from app.audit import log_event
from app.db import get_db
from app.models import Target, User, utcnow
from app.ratelimit import rate_limit
from app.schemas import TargetIn
from app.security import new_token, safe_equal
from app.sessions import get_current_user, require_csrf
from app.ssrf import TargetRejected, is_allowed_ip, lab_mode_enabled, parse_origin, safe_get

router = APIRouter(tags=["targets"])
writers = require_role("tester", "admin")

WELL_KNOWN_PATH = "/.well-known/scopeguard-verification.txt"
REVERIFY_AFTER = timedelta(days=30)


def is_verified_fresh(t: Target) -> bool:
    """Ownership proof goes stale: scans must only run on targets verified recently."""
    return bool(t.verified and t.verified_at and utcnow() - t.verified_at < REVERIFY_AFTER)


def target_out(t: Target) -> dict:
    fresh = is_verified_fresh(t)
    out = {
        "id": str(t.id),
        "engagement_id": str(t.engagement_id),
        "base_url": t.base_url,
        "verified": fresh,
        "verified_at": t.verified_at.isoformat() if t.verified_at else None,
        "verification_path": WELL_KNOWN_PATH,
    }
    if not fresh:
        out["verification_token"] = t.verification_token  # meant to be published on the target
    return out


def check_token(t: Target) -> tuple[bool, str]:
    """Reasons are a fixed set, so error text cannot leak details about internal networks."""
    try:
        res = safe_get(t.base_url, WELL_KNOWN_PATH, max_bytes=4096)
    except TargetRejected:
        return False, "target_not_allowed"
    except (httpx.HTTPError, httpx.InvalidURL, OSError):
        return False, "target_unreachable"
    if res.status != 200 or res.truncated:
        return False, "token_not_found"
    body = res.body.decode("utf-8", "ignore").strip()
    if not t.verification_token or not safe_equal(body, t.verification_token):
        return False, "token_not_found"
    return True, "ok"


@router.post("/engagements/{engagement_id}/targets", status_code=201)
def create_target(
    engagement_id: uuid.UUID,
    body: TargetIn,
    user: User = Depends(writers),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    eng = get_engagement_or_404(db, user, engagement_id)
    try:
        origin = parse_origin(body.base_url)
    except TargetRejected:
        raise HTTPException(status_code=422, detail="Invalid target URL")
    if origin.host_is_ip and not is_allowed_ip(origin.host, lab_mode=lab_mode_enabled()):
        raise HTTPException(status_code=422, detail="Target address is not allowed")
    exists = db.scalar(
        select(Target).where(Target.engagement_id == eng.id, Target.base_url == origin.url)
    )
    if exists is not None:
        raise HTTPException(status_code=409, detail="Target already exists in this engagement")
    target = Target(
        engagement_id=eng.id, base_url=origin.url, verified=False, verification_token=new_token()
    )
    db.add(target)
    db.commit()
    log_event(db, "target_created", user.id, f"target={target.id} engagement={eng.id}")
    return target_out(target)


@router.get("/engagements/{engagement_id}/targets")
def list_targets(
    engagement_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    eng = get_engagement_or_404(db, user, engagement_id)
    rows = db.scalars(select(Target).where(Target.engagement_id == eng.id).order_by(Target.created_at))
    return [target_out(t) for t in rows]


@router.post("/targets/{target_id}/verify", dependencies=[Depends(rate_limit("verify", 10, 60))])
def verify_target(
    target_id: uuid.UUID,
    user: User = Depends(writers),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    target = get_target_or_404(db, user, target_id)
    ok, reason = check_token(target)
    if not ok:
        log_event(db, "target_verify_failed", user.id, f"target={target.id} reason={reason}")
        raise HTTPException(status_code=400, detail=f"Verification failed: {reason}")
    target.verified = True
    target.verified_at = utcnow()
    db.commit()
    log_event(db, "target_verified", user.id, f"target={target.id}")
    return target_out(target)


@router.delete("/targets/{target_id}", status_code=204)
def delete_target(
    target_id: uuid.UUID,
    user: User = Depends(writers),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    target = get_target_or_404(db, user, target_id)
    tid = target.id
    db.delete(target)
    db.commit()
    log_event(db, "target_deleted", user.id, f"target={tid}")
