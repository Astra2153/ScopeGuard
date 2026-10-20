import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.config import settings
from app.db import SessionLocal
from app.main import app
from app.models import User
from app.ratelimit import reset_limits

PASSWORD = "correct-horse-battery-1"


@pytest.fixture(autouse=True)
def cleanup_test_users():
    yield
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email.like("%@example.test")))
        db.commit()


def enable_limits(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    reset_limits()


def test_login_is_rate_limited_per_ip(monkeypatch):
    enable_limits(monkeypatch)
    c = TestClient(app)
    body = {"email": f"rl_{uuid.uuid4().hex[:10]}@example.test", "password": "wrong-password-123"}
    codes = [c.post("/auth/login", json=body).status_code for _ in range(10)]
    assert codes == [401] * 10
    blocked = c.post("/auth/login", json=body)
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1


def test_register_is_rate_limited_per_ip(monkeypatch):
    enable_limits(monkeypatch)
    c = TestClient(app)
    codes = []
    for _ in range(6):
        email = f"rl_{uuid.uuid4().hex[:10]}@example.test"
        codes.append(c.post("/auth/register", json={"email": email, "password": PASSWORD}).status_code)
    assert codes == [201] * 5 + [429]


def test_limits_are_separate_per_route(monkeypatch):
    enable_limits(monkeypatch)
    c = TestClient(app)
    body = {"email": f"rl_{uuid.uuid4().hex[:10]}@example.test", "password": "wrong-password-123"}
    for _ in range(11):
        c.post("/auth/login", json=body)
    assert c.post("/auth/login", json=body).status_code == 429
    email = f"rl_{uuid.uuid4().hex[:10]}@example.test"
    assert c.post("/auth/register", json={"email": email, "password": PASSWORD}).status_code == 201


def test_limiter_is_off_in_other_tests():
    c = TestClient(app)
    body = {"email": f"rl_{uuid.uuid4().hex[:10]}@example.test", "password": "wrong-password-123"}
    assert all(c.post("/auth/login", json=body).status_code == 401 for _ in range(12))
