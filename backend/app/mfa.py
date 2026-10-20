import hmac
import secrets
import time

import pyotp
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from app.audit import log_event
from app.crypto import decrypt, encrypt, keyed_hash
from app.db import get_db
from app.models import BackupCode, User
from app.ratelimit import rate_limit
from app.schemas import MfaCodeIn, MfaDisableIn
from app.security import verify_password
from app.sessions import get_current_user, require_csrf

router = APIRouter(
    prefix="/auth/mfa", tags=["mfa"], dependencies=[Depends(rate_limit("mfa", 10, 60))]
)

STEP_SECONDS = 30


def _totp(user: User) -> pyotp.TOTP:
    return pyotp.TOTP(decrypt(user.mfa_secret, aad=str(user.id)))


def verify_totp(user: User, code: str) -> int | None:
    """Return the accepted time step, or None. Accepts +/-1 step for clock drift.
    A step at or below the last used one is rejected, so a code works only once."""
    code = code.strip()
    if not user.mfa_secret or not (code.isascii() and code.isdigit() and len(code) == 6):
        return None
    totp = _totp(user)
    now_step = int(time.time() // STEP_SECONDS)
    for step in (now_step - 1, now_step, now_step + 1):
        if step > user.mfa_last_step and hmac.compare_digest(totp.at(step * STEP_SECONDS), code):
            return step
    return None


def generate_backup_codes(db: DbSession, user: User) -> list[str]:
    db.execute(delete(BackupCode).where(BackupCode.user_id == user.id))
    codes = []
    for _ in range(8):
        raw = secrets.token_hex(5)  # 10 hex characters
        codes.append(f"{raw[:5]}-{raw[5:]}")
        db.add(BackupCode(user_id=user.id, code_hash=keyed_hash(raw)))
    return codes


def use_backup_code(db: DbSession, user: User, code: str) -> bool:
    raw = code.strip().lower().replace("-", "")
    if len(raw) != 10:
        return False
    row = db.scalar(
        select(BackupCode).where(
            BackupCode.user_id == user.id,
            BackupCode.code_hash == keyed_hash(raw),
            BackupCode.used.is_(False),
        )
    )
    if row is None:
        return False
    row.used = True  # each backup code works exactly once
    return True


def verify_second_factor(db: DbSession, user: User, code: str) -> bool:
    step = verify_totp(user, code)
    if step is not None:
        user.mfa_last_step = step
        return True
    return use_backup_code(db, user, code)


@router.post("/setup")
def setup(
    user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA is already enabled")
    secret = pyotp.random_base32()
    user.mfa_secret = encrypt(secret, aad=str(user.id))  # stored encrypted, never in plaintext
    user.mfa_last_step = 0
    db.commit()
    log_event(db, "mfa_setup", user.id)
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="ScopeGuard")
    return {"secret": secret, "otpauth_uri": uri}  # shown once, so it can be added to an app


@router.post("/enable")
def enable(
    body: MfaCodeIn,
    user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA is already enabled")
    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="Run setup first")
    step = verify_totp(user, body.code)
    if step is None:
        raise HTTPException(status_code=400, detail="Invalid code")
    user.mfa_enabled = True
    user.mfa_last_step = step
    codes = generate_backup_codes(db, user)
    db.commit()
    log_event(db, "mfa_enabled", user.id)
    return {"backup_codes": codes}  # shown once; only keyed hashes are stored


@router.post("/disable", status_code=204)
def disable(
    body: MfaDisableIn,
    user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    if not user.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA is not enabled")
    # Turning MFA off needs the password AND a valid second factor.
    if not verify_password(user.password_hash, body.password) or not verify_second_factor(
        db, user, body.code
    ):
        log_event(db, "mfa_disable_failed", user.id)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_last_step = 0
    db.execute(delete(BackupCode).where(BackupCode.user_id == user.id))
    db.commit()
    log_event(db, "mfa_disabled", user.id)
