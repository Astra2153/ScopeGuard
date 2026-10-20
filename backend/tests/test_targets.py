import socket
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

from app.config import settings
from app.db import SessionLocal
from app.main import app
from app.models import AuditLog, User
from app.ratelimit import reset_limits
from app.targets import WELL_KNOWN_PATH

PASSWORD = "correct-horse-battery-1"


@pytest.fixture(autouse=True)
def cleanup_test_users():
    yield
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email.like("%@example.test")))
        db.commit()


class Actor:
    def __init__(self):
        self.client = TestClient(app)
        self.email = f"t_{uuid.uuid4().hex[:12]}@example.test"
        r = self.client.post("/auth/register", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 201
        r = self.client.post("/auth/login", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 200
        self.csrf = r.json()["csrf_token"]

    def call(self, method, url, json=None):
        return self.client.request(method, url, json=json, headers={"X-CSRF-Token": self.csrf})

    def make_engagement(self):
        r = self.call("POST", "/engagements", {"name": "Acme API"})
        assert r.status_code == 201
        return r.json()["id"]

    def add_target(self, eng_id, url):
        r = self.call("POST", f"/engagements/{eng_id}/targets", {"base_url": url})
        assert r.status_code == 201, r.text
        return r.json()


def set_role(email, role):
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        user.role = role
        db.commit()


def max_audit_id():
    with SessionLocal() as db:
        return db.scalar(select(func.max(AuditLog.id))) or 0


def events_since(start_id):
    with SessionLocal() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.id > start_id).order_by(AuditLog.id)))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_create_target_returns_token_and_normalized_origin():
    a = Actor()
    eng = a.make_engagement()
    t = a.add_target(eng, "https://API.Example.com/v1/users?x=1")
    assert t["base_url"] == "https://api.example.com"
    assert t["verified"] is False
    assert t["verification_path"] == WELL_KNOWN_PATH
    assert len(t["verification_token"]) >= 40


@pytest.mark.parametrize(
    "url", ["ftp://example.com", "http://user:pw@example.com", "not a url", "http://127.0.0.1/"]
)
def test_invalid_or_blocked_urls_rejected_on_create(url):
    a = Actor()
    eng = a.make_engagement()
    r = a.call("POST", f"/engagements/{eng}/targets", {"base_url": url})
    assert r.status_code == 422


def test_duplicate_target_rejected():
    a = Actor()
    eng = a.make_engagement()
    a.add_target(eng, "https://api.example.com")
    r = a.call("POST", f"/engagements/{eng}/targets", {"base_url": "https://API.example.com/other"})
    assert r.status_code == 409


def test_tokens_are_unique():
    a = Actor()
    eng = a.make_engagement()
    t1 = a.add_target(eng, "https://one.example.com")
    t2 = a.add_target(eng, "https://two.example.com")
    assert t1["verification_token"] != t2["verification_token"]


def test_user_b_cannot_touch_user_a_targets():
    a, b = Actor(), Actor()
    eng = a.make_engagement()
    t = a.add_target(eng, "https://api.example.com")
    assert b.call("GET", f"/engagements/{eng}/targets").status_code == 404
    assert b.call("POST", f"/engagements/{eng}/targets", {"base_url": "https://x.example.com"}).status_code == 404
    assert b.call("POST", f"/targets/{t['id']}/verify").status_code == 404
    assert b.call("DELETE", f"/targets/{t['id']}").status_code == 404
    assert len(a.call("GET", f"/engagements/{eng}/targets").json()) == 1


def test_unauthenticated_requests_rejected():
    anon = TestClient(app)
    assert anon.get(f"/engagements/{uuid.uuid4()}/targets").status_code == 401
    assert anon.post(f"/targets/{uuid.uuid4()}/verify").status_code == 401
    assert anon.delete(f"/targets/{uuid.uuid4()}").status_code == 401


def test_verify_requires_csrf():
    a = Actor()
    t = a.add_target(a.make_engagement(), "https://api.example.com")
    assert a.client.post(f"/targets/{t['id']}/verify").status_code == 403


def test_client_viewer_cannot_add_targets():
    a = Actor()
    eng = a.make_engagement()
    set_role(a.email, "client_viewer")
    assert a.call("POST", f"/engagements/{eng}/targets", {"base_url": "https://x.example.com"}).status_code == 403


def test_verify_succeeds_when_token_is_served(lab_mode, lab_server):
    a = Actor()
    t = a.add_target(a.make_engagement(), lab_server.origin)
    lab_server.token = t["verification_token"]
    r = a.call("POST", f"/targets/{t['id']}/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is True and body["verified_at"]
    assert "verification_token" not in body  # not shown again once verified
    assert ("GET", WELL_KNOWN_PATH, f"127.0.0.1:{lab_server.port}") in lab_server.hits


def test_verify_fails_with_wrong_token(lab_mode, lab_server):
    a = Actor()
    t = a.add_target(a.make_engagement(), lab_server.origin)
    lab_server.token = "someone-elses-token"
    r = a.call("POST", f"/targets/{t['id']}/verify")
    assert r.status_code == 400 and r.json()["detail"] == "Verification failed: token_not_found"
    eng_targets = a.call("GET", f"/engagements/{t['engagement_id']}/targets").json()
    assert eng_targets[0]["verified"] is False


def test_verify_fails_when_no_token_file(lab_mode, lab_server):
    a = Actor()
    t = a.add_target(a.make_engagement(), lab_server.origin)  # server has no token set: 404
    r = a.call("POST", f"/targets/{t['id']}/verify")
    assert r.status_code == 400 and r.json()["detail"] == "Verification failed: token_not_found"


def test_policy_is_rechecked_at_verify_time(lab_mode, lab_server, monkeypatch):
    a = Actor()
    t = a.add_target(a.make_engagement(), lab_server.origin)  # allowed while lab mode is on
    lab_server.token = t["verification_token"]
    monkeypatch.setattr(settings, "allow_private_targets", False)  # policy tightened afterwards
    r = a.call("POST", f"/targets/{t['id']}/verify")
    assert r.status_code == 400 and r.json()["detail"] == "Verification failed: target_not_allowed"
    assert lab_server.hits == []  # the request never left ScopeGuard


def test_unreachable_target_reported(lab_mode):
    a = Actor()
    t = a.add_target(a.make_engagement(), f"http://127.0.0.1:{free_port()}")
    r = a.call("POST", f"/targets/{t['id']}/verify")
    assert r.status_code == 400 and r.json()["detail"] == "Verification failed: target_unreachable"


def test_verify_is_rate_limited(lab_mode, lab_server, monkeypatch):
    a = Actor()
    t = a.add_target(a.make_engagement(), lab_server.origin)
    monkeypatch.setattr(settings, "allow_private_targets", False)  # verify is refused instantly
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    reset_limits()
    codes = [a.call("POST", f"/targets/{t['id']}/verify").status_code for _ in range(10)]
    assert codes == [400] * 10
    assert a.call("POST", f"/targets/{t['id']}/verify").status_code == 429


def test_target_events_are_audited_with_ids_only(lab_mode, lab_server):
    a = Actor()
    eng = a.make_engagement()
    start = max_audit_id()
    t = a.add_target(eng, lab_server.origin)
    a.call("POST", f"/targets/{t['id']}/verify")  # fails: no token served yet
    lab_server.token = t["verification_token"]
    a.call("POST", f"/targets/{t['id']}/verify")  # succeeds
    a.call("DELETE", f"/targets/{t['id']}")
    rows = events_since(start)
    assert [r.action for r in rows] == [
        "target_created", "target_verify_failed", "target_verified", "target_deleted",
    ]
    blob = " ".join(r.detail for r in rows)
    assert lab_server.origin not in blob and t["verification_token"] not in blob
