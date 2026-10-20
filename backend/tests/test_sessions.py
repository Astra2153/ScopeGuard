import hashlib
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.db import SessionLocal
from app.main import app
from app.models import Session as SessionRow
from app.models import User, utcnow

PASSWORD = "correct-horse-battery-1"


def new_email() -> str:
    return f"s_{uuid.uuid4().hex[:12]}@example.test"


@pytest.fixture(autouse=True)
def cleanup_test_users():
    yield
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email.like("%@example.test")))
        db.commit()


def make_user():
    c = TestClient(app)
    email = new_email()
    assert c.post("/auth/register", json={"email": email, "password": PASSWORD}).status_code == 201
    return c, email


def login(c: TestClient, email: str):
    r = c.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200
    return r


def test_login_sets_httponly_samesite_cookie():
    c, email = make_user()
    header = login(c, email).headers["set-cookie"].lower()
    assert "sg_session=" in header
    assert "httponly" in header
    assert "samesite=lax" in header


def test_session_token_is_stored_only_as_hash():
    c, email = make_user()
    login(c, email)
    token = c.cookies.get("sg_session")
    with SessionLocal() as db:
        assert db.scalar(select(SessionRow).where(SessionRow.token_hash == token)) is None
        digest = hashlib.sha256(token.encode()).hexdigest()
        assert db.scalar(select(SessionRow).where(SessionRow.token_hash == digest)) is not None


def test_me_requires_login():
    assert TestClient(app).get("/auth/me").status_code == 401


def test_me_returns_current_user():
    c, email = make_user()
    login(c, email)
    r = c.get("/auth/me")
    assert r.status_code == 200
    assert r.json()["email"] == email


def test_tampered_cookie_rejected():
    r = TestClient(app).get("/auth/me", headers={"Cookie": "sg_session=not-a-real-token"})
    assert r.status_code == 401


def test_logout_requires_csrf_header():
    c, email = make_user()
    login(c, email)
    assert c.post("/auth/logout").status_code == 403
    assert c.post("/auth/logout", headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert c.get("/auth/me").status_code == 200  # still logged in


def test_logout_ends_session_server_side():
    c, email = make_user()
    r = login(c, email)
    token = c.cookies.get("sg_session")
    assert c.post("/auth/logout", headers={"X-CSRF-Token": r.json()["csrf_token"]}).status_code == 204
    assert c.get("/auth/me").status_code == 401
    # Replaying the old token on a fresh client must fail too.
    replay = TestClient(app).get("/auth/me", headers={"Cookie": f"sg_session={token}"})
    assert replay.status_code == 401


def test_login_rotates_session_token():
    c, email = make_user()
    login(c, email)
    token1 = c.cookies.get("sg_session")
    login(c, email)
    token2 = c.cookies.get("sg_session")
    assert token1 != token2
    replay = TestClient(app).get("/auth/me", headers={"Cookie": f"sg_session={token1}"})
    assert replay.status_code == 401


def test_session_fixation_attacker_token_is_not_accepted():
    c, email = make_user()
    r = c.post(
        "/auth/login",
        json={"email": email, "password": PASSWORD},
        headers={"Cookie": "sg_session=attacker-chosen-value"},
    )
    assert r.status_code == 200
    assert c.cookies.get("sg_session") != "attacker-chosen-value"


def test_expired_session_rejected():
    c, email = make_user()
    login(c, email)
    token = c.cookies.get("sg_session")
    with SessionLocal() as db:
        row = db.scalar(
            select(SessionRow).where(SessionRow.token_hash == hashlib.sha256(token.encode()).hexdigest())
        )
        row.expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    assert c.get("/auth/me").status_code == 401
