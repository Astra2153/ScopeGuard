from datetime import timedelta

from fastapi import Cookie, Depends, Header, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.config import settings
from app.db import get_db
from app.models import Session, User, utcnow
from app.security import hash_token, new_token, safe_equal

COOKIE_NAME = "sg_session"
NOT_AUTHENTICATED = "Not authenticated"


def create_session(db: DbSession, user: User) -> tuple[str, Session]:
    token = new_token()
    row = Session(
        user_id=user.id,
        token_hash=hash_token(token),  # only the hash is stored, never the token
        csrf_token=new_token(),
        expires_at=utcnow() + timedelta(hours=settings.session_hours),
    )
    db.add(row)
    db.commit()
    return token, row


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=settings.session_hours * 3600,
        httponly=True,  # JavaScript cannot read it
        secure=settings.cookie_secure,  # HTTPS only when enabled
        samesite="lax",
        path="/",
    )


def get_current_session(
    sg_session: str | None = Cookie(default=None), db: DbSession = Depends(get_db)
) -> Session:
    # Fail closed: any problem means 401 with the same message.
    if not sg_session:
        raise HTTPException(status_code=401, detail=NOT_AUTHENTICATED)
    row = db.scalar(select(Session).where(Session.token_hash == hash_token(sg_session)))
    if row is None:
        raise HTTPException(status_code=401, detail=NOT_AUTHENTICATED)
    if row.expires_at <= utcnow():
        db.delete(row)
        db.commit()
        raise HTTPException(status_code=401, detail=NOT_AUTHENTICATED)
    return row


def get_current_user(
    session: Session = Depends(get_current_session), db: DbSession = Depends(get_db)
) -> User:
    user = db.get(User, session.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail=NOT_AUTHENTICATED)
    return user


def require_csrf(
    x_csrf_token: str | None = Header(default=None),
    session: Session = Depends(get_current_session),
) -> None:
    if not x_csrf_token or not safe_equal(x_csrf_token, session.csrf_token):
        raise HTTPException(status_code=403, detail="CSRF check failed")
