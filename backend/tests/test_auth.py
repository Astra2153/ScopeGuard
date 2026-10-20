import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.db import SessionLocal
from app.main import app
from app.models import User, utcnow
from app.security import hash_password

client = TestClient(app)
PASSWORD = "correct-horse-battery-1"


def new_email() -> str:
    return f"u_{uuid.uuid4().hex[:12]}@example.test"


@pytest.fixture(autouse=True)
def cleanup_test_users():
    yield
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email.like("%@example.test")))
        db.commit()


def register(email: str, password: str = PASSWORD):
    return client.post("/auth/register", json={"email": email, "password": password})


def test_password_hash_is_argon2id_and_salted():
    h1 = hash_password(PASSWORD)
    h2 = hash_password(PASSWORD)
    assert h1.startswith("$argon2id$")
    assert PASSWORD not in h1
    assert h1 != h2  # different random salt each time


def test_register_ok_and_hash_stored_not_password():
    email = new_email()
    r = register(email)
    assert r.status_code == 201
    assert "password" not in r.text
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        assert user.password_hash.startswith("$argon2id$")
        assert user.role == "tester"


def test_register_cannot_choose_role():
    r = client.post(
        "/auth/register",
        json={"email": new_email(), "password": PASSWORD, "role": "admin"},
    )
    assert r.status_code == 422


def test_short_password_rejected():
    assert register(new_email(), "short").status_code == 422


def test_duplicate_email_rejected():
    email = new_email()
    assert register(email).status_code == 201
    assert register(email).status_code == 409


def test_login_success():
    email = new_email()
    register(email)
    r = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200


def test_login_errors_do_not_reveal_whether_email_exists():
    email = new_email()
    register(email)
    wrong_password = client.post("/auth/login", json={"email": email, "password": "wrong-password-123"})
    unknown_email = client.post("/auth/login", json={"email": new_email(), "password": "wrong-password-123"})
    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()


def test_lockout_after_repeated_failures_then_recovers():
    email = new_email()
    register(email)
    for _ in range(5):
        r = client.post("/auth/login", json={"email": email, "password": "wrong-password-123"})
        assert r.status_code == 401
    # Locked: even the correct password is refused, with the same generic error.
    locked = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert locked.status_code == 401
    assert locked.json() == {"detail": "Invalid email or password"}
    # Simulate the lock period ending.
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        user.locked_until = utcnow() - timedelta(minutes=1)
        db.commit()
    ok = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert ok.status_code == 200
