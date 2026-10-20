from datetime import timedelta

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from app.db import get_db
from app.mfa import verify_second_factor
from app.models import Session, User, utcnow
from app.ratelimit import rate_limit
from app.schemas import LoginIn, RegisterIn
from app.security import DUMMY_HASH, hash_password, hash_token, needs_rehash, verify_password
from app.sessions import (
    COOKIE_NAME,
    create_session,
    get_current_session,
    get_current_user,
    require_csrf,
    set_session_cookie,
)

router = APIRouter(prefix="/auth", tags=["auth"])

MAX_FAILED = 5
LOCK_MINUTES = 15
GENERIC_LOGIN_ERROR = "Invalid email or password"
MFA_REQUIRED = "MFA code required"


def record_failure(db: DbSession, user: User, now) -> None:
    user.failed_logins += 1
    if user.failed_logins >= MAX_FAILED:
        user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
        user.failed_logins = 0
    db.commit()


@router.post("/register", status_code=201, dependencies=[Depends(rate_limit("register", 5, 60))])
def register(body: RegisterIn, db: DbSession = Depends(get_db)):
    user = User(
        email=body.email.strip().lower(),
        password_hash=hash_password(body.password),
        role="tester",  # role is never taken from user input
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Could not register with these details")
    return {"id": str(user.id), "email": user.email, "role": user.role}


@router.post("/login", dependencies=[Depends(rate_limit("login", 10, 60))])
def login(
    body: LoginIn,
    response: Response,
    sg_session: str | None = Cookie(default=None),
    db: DbSession = Depends(get_db),
):
    email = body.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))

    if user is None:
        # Spend similar time as a real check, then give the same generic error.
        verify_password(DUMMY_HASH, body.password)
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

    now = utcnow()
    locked = user.locked_until is not None and user.locked_until > now
    password_ok = verify_password(user.password_hash, body.password)

    if locked or not password_ok:
        if not locked:
            record_failure(db, user, now)
        # Same error whether locked, wrong password, or unknown email.
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

    if user.mfa_enabled:
        if not body.otp:
            raise HTTPException(status_code=401, detail=MFA_REQUIRED)
        if not verify_second_factor(db, user, body.otp):
            record_failure(db, user, now)  # wrong MFA codes count toward lockout
            raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

    user.failed_logins = 0
    user.locked_until = None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    db.commit()

    # Session rotation: drop any session the browser sent, always issue a brand-new one.
    if sg_session:
        db.execute(delete(Session).where(Session.token_hash == hash_token(sg_session)))
        db.commit()
    token, row = create_session(db, user)
    set_session_cookie(response, token)
    return {"status": "ok", "csrf_token": row.csrf_token}


@router.get("/me")
def me(user: User = Depends(get_current_user), session: Session = Depends(get_current_session)):
    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "mfa_enabled": user.mfa_enabled,
        "csrf_token": session.csrf_token,
    }


@router.post("/logout", status_code=204)
def logout(
    response: Response,
    session: Session = Depends(get_current_session),
    _csrf: None = Depends(require_csrf),
    db: DbSession = Depends(get_db),
):
    db.delete(session)
    db.commit()
    response.delete_cookie(COOKIE_NAME, path="/")
