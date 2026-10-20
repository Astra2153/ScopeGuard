import json
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.access import get_target_or_404, require_role
from app.audit import log_event
from app.db import get_db
from app.matrix import (
    MatrixError,
    extract_endpoints,
    run_matrix,
    validate_auth,
    validate_object_ids,
)
from app.models import Finding, User
from app.ratelimit import rate_limit
from app.sessions import require_csrf
from app.targets import is_verified_fresh

router = APIRouter(tags=["authz"])
writers = require_role("tester", "admin")


class AuthzScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm_authorized: Literal[True]  # "I have written authorisation to test this target"
    spec: dict
    auth_a: dict[str, str]
    auth_b: dict[str, str]
    object_ids: dict[str, str]

    @field_validator("spec")
    @classmethod
    def _spec_size(cls, value):
        if len(json.dumps(value)) > 500_000:
            raise ValueError("spec too large")
        return value


@router.post("/targets/{target_id}/authz-scan", dependencies=[Depends(rate_limit("authz", 2, 60))])
def authz_scan(
    target_id: uuid.UUID,
    body: AuthzScanIn,
    user: User = Depends(writers),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    target = get_target_or_404(db, user, target_id)
    # Fail closed: no fresh proof of ownership means nothing is sent to the target.
    if not is_verified_fresh(target):
        raise HTTPException(status_code=409, detail="Target is not verified")
    try:
        auth_a = validate_auth(body.auth_a)
        auth_b = validate_auth(body.auth_b)
        object_ids = validate_object_ids(body.object_ids)
    except MatrixError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid input: {exc.reason}")
    if auth_a == auth_b:
        raise HTTPException(status_code=422, detail="Invalid input: identities_must_differ")
    endpoints = extract_endpoints(body.spec)
    if not endpoints:
        raise HTTPException(status_code=422, detail="Invalid input: no_testable_endpoints")

    # The audit trail records the confirmation, the target and counts. Never credentials or paths.
    log_event(
        db, "authz_scan_started", user.id,
        f"target={target.id} endpoints={len(endpoints)} authorization_confirmed=true",
    )
    try:
        report = run_matrix(target.base_url, endpoints, auth_a, auth_b, object_ids)
    except MatrixError as exc:
        log_event(db, "authz_scan_failed", user.id, f"target={target.id} reason={exc.reason}")
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
                source="authz",
                fingerprint=fingerprint,
            ))
            created += 1
        elif existing.status in ("fixed", "partially_fixed"):
            existing.status = "not_fixed"  # reproduced after being marked fixed
            reopened += 1
        else:
            unchanged += 1
    db.commit()

    confirmed = sum(1 for r in report.results if r.outcome == "confirmed_bola")
    anonymous = sum(1 for r in report.results if r.anonymous)
    log_event(
        db, "authz_scan_finished", user.id,
        f"target={target.id} tested={len(report.results)} confirmed={confirmed} anonymous={anonymous} "
        f"created={created} reopened={reopened} unchanged={unchanged} "
        f"requests={report.requests} incomplete={report.incomplete}",
    )
    return {
        "results": [
            {"path": r.path, "outcome": r.outcome, "anonymous_access": r.anonymous}
            for r in report.results
        ],
        "created": created,
        "reopened": reopened,
        "unchanged": unchanged,
        "requests": report.requests,
        "incomplete": report.incomplete,
    }
