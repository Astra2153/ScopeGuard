import uuid

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session as DbSession

from app.models import Engagement, Finding, Target, User
from app.sessions import get_current_user

NOT_FOUND = "Not found"


def require_role(*roles: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return checker


def can_access(user: User, engagement: Engagement) -> bool:
    return user.role == "admin" or engagement.owner_id == user.id


def get_engagement_or_404(db: DbSession, user: User, engagement_id: uuid.UUID) -> Engagement:
    # Missing and not-yours look identical, so object existence is not leaked.
    eng = db.get(Engagement, engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    return eng


def get_finding_or_404(db: DbSession, user: User, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    eng = db.get(Engagement, finding.engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    return finding


def get_target_or_404(db: DbSession, user: User, target_id: uuid.UUID) -> Target:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    eng = db.get(Engagement, target.engagement_id)
    if eng is None or not can_access(user, eng):
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    return target
