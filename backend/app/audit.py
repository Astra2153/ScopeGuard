import json
import uuid
from datetime import timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select, text
from sqlalchemy.orm import Session as DbSession

from app.access import require_role
from app.crypto import keyed_hash
from app.db import get_db
from app.models import AuditLog, User, utcnow

GENESIS_HASH = "0" * 64
CHAIN_LOCK_KEY = 727001  # arbitrary constant id for the Postgres advisory lock
MAX_DETAIL = 500


def compute_hash(prev_hash: str, ts, actor_id, action: str, detail: str) -> str:
    # A JSON list is unambiguous: no field can bleed into the next one.
    payload = json.dumps(
        [
            prev_hash,
            ts.astimezone(timezone.utc).isoformat(),
            str(actor_id) if actor_id else None,
            action,
            detail,
        ],
        separators=(",", ":"),
    )
    return keyed_hash(payload)  # HMAC with a server-side key


def log_event(db: DbSession, action: str, actor_id: uuid.UUID | None = None, detail: str = "") -> None:
    """Append one entry. Callers pass fixed strings and IDs only, never secrets or free text."""
    # Serialise appenders so the chain cannot fork. The lock is released at commit.
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": CHAIN_LOCK_KEY})
    prev = (
        db.scalar(select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1)) or GENESIS_HASH
    )
    ts = utcnow()
    detail = detail[:MAX_DETAIL]
    db.add(
        AuditLog(
            ts=ts,
            actor_id=actor_id,
            action=action,
            detail=detail,
            prev_hash=prev,
            entry_hash=compute_hash(prev, ts, actor_id, action, detail),
        )
    )
    db.commit()  # if hashing or the insert fails, the error propagates (fail closed)


def verify_chain(db: DbSession) -> dict:
    expected_prev = GENESIS_HASH
    checked = 0
    for row in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        recomputed = compute_hash(row.prev_hash, row.ts, row.actor_id, row.action, row.detail)
        if row.prev_hash != expected_prev or row.entry_hash != recomputed:
            return {"ok": False, "entries_checked": checked, "first_bad_id": row.id}
        expected_prev = row.entry_hash
        checked += 1
    return {"ok": True, "entries_checked": checked, "first_bad_id": None}


router = APIRouter(prefix="/audit", tags=["audit"])
admin_only = require_role("admin")


@router.get("")
def list_events(_admin: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(100))
    return [
        {
            "id": r.id,
            "ts": r.ts.isoformat(),
            "actor_id": str(r.actor_id) if r.actor_id else None,
            "action": r.action,
            "detail": r.detail,
        }
        for r in rows
    ]


@router.get("/verify")
def verify(_admin: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    return verify_chain(db)
