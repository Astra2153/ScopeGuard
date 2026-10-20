from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User, utcnow
from app.schemas import LoginIn, RegisterIn
from app.security import DUMMY_HASH, hash_password, needs_rehash, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

MAX_FAILED = 5
LOCK_MINUTES = 15
GENERIC_LOGIN_ERROR = "Invalid email or password"


@router.post("/register", status_code=201)
def register(body: RegisterIn, db: Session = Depends(get_db)):
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


@router.post("/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
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
            user.failed_logins += 1
            if user.failed_logins >= MAX_FAILED:
                user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
                user.failed_logins = 0
            db.commit()
        # Same error whether the account is locked, the password is wrong, or the email is unknown.
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

    user.failed_logins = 0
    user.locked_until = None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    db.commit()
    # Session creation and MFA are added in the next step.
    return {"status": "ok"}
