import uuid
from concurrent.futures import ThreadPoolExecutor

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import DBAPIError

from app.audit import log_event, verify_chain
from app.config import settings
from app.crypto import CryptoError
from app.db import SessionLocal
from app.main import app
from app.models import AuditLog, User

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
        self.email = f"au_{uuid.uuid4().hex[:12]}@example.test"
        r = self.client.post("/auth/register", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 201
        self.id = r.json()["id"]
        r = self.client.post("/auth/login", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 200
        self.csrf = r.json()["csrf_token"]

    def call(self, method, url, json=None):
        return self.client.request(method, url, json=json, headers={"X-CSRF-Token": self.csrf})


def set_role(email: str, role: str):
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        user.role = role
        db.commit()


def max_id() -> int:
    with SessionLocal() as db:
        return db.scalar(select(func.max(AuditLog.id))) or 0


def events_since(start_id: int):
    with SessionLocal() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.id > start_id).order_by(AuditLog.id)))


def seed_events(n: int = 6):
    with SessionLocal() as db:
        for i in range(n):
            log_event(db, "seed", None, f"i={i}")


def last_ids(n: int):
    with SessionLocal() as db:
        return sorted(db.scalars(select(AuditLog.id).order_by(AuditLog.id.desc()).limit(n)))


def test_register_login_logout_are_audited():
    start = max_id()
    a = Actor()
    assert a.call("POST", "/auth/logout").status_code == 204
    rows = events_since(start)
    assert [r.action for r in rows] == ["register", "login_success", "logout"]
    assert all(str(r.actor_id) == a.id for r in rows)


def test_failed_logins_logged_without_secrets():
    start = max_id()
    ghost = f"ghost_{uuid.uuid4().hex[:8]}@example.test"
    guess = "attacker-guess-999"
    c = TestClient(app)
    c.post("/auth/login", json={"email": ghost, "password": guess})
    a = Actor()
    c.post("/auth/login", json={"email": a.email, "password": guess})
    rows = events_since(start)
    actions = [r.action for r in rows]
    assert "login_failed_unknown_account" in actions
    assert "login_failed_bad_password" in actions
    blob = " ".join(f"{r.action} {r.detail}" for r in rows)
    for secret in (ghost, a.email, guess, PASSWORD):
        assert secret not in blob


def test_lockout_is_audited():
    a = Actor()
    start = max_id()
    c = TestClient(app)
    for _ in range(5):
        c.post("/auth/login", json={"email": a.email, "password": "attacker-guess-999"})
    c.post("/auth/login", json={"email": a.email, "password": PASSWORD})
    actions = [r.action for r in events_since(start)]
    assert actions.count("login_failed_bad_password") == 5
    assert "account_locked" in actions
    assert actions[-1] == "login_blocked_locked"


def test_mfa_changes_are_audited():
    start = max_id()
    a = Actor()
    secret = a.call("POST", "/auth/mfa/setup").json()["secret"]
    codes = a.call("POST", "/auth/mfa/enable", {"code": pyotp.TOTP(secret).now()}).json()["backup_codes"]
    r = a.call("POST", "/auth/mfa/disable", {"password": PASSWORD, "code": codes[0]})
    assert r.status_code == 204
    rows = events_since(start)
    assert [r.action for r in rows] == [
        "register", "login_success", "mfa_setup", "mfa_enabled", "mfa_disabled",
    ]
    blob = " ".join(f"{r.action} {r.detail}" for r in rows)
    assert secret not in blob and not any(code in blob for code in codes)


def test_data_changes_are_audited_without_user_text():
    a = Actor()
    start = max_id()
    eng_id = a.call("POST", "/engagements", {"name": "Acme"}).json()["id"]
    f_id = a.call(
        "POST", f"/engagements/{eng_id}/findings",
        {"title": "x\nFAKE_LOG_ENTRY forged line", "severity": "high"},
    ).json()["id"]
    a.call("PATCH", f"/findings/{f_id}", {"status": "fixed"})
    a.call("DELETE", f"/findings/{f_id}")
    a.call("DELETE", f"/engagements/{eng_id}")
    rows = events_since(start)
    assert [r.action for r in rows] == [
        "engagement_created", "finding_created", "finding_status_changed",
        "finding_deleted", "engagement_deleted",
    ]
    assert all("FAKE_LOG_ENTRY" not in r.detail for r in rows)  # no log injection


def test_each_entry_links_to_previous_hash():
    seed_events(4)
    with SessionLocal() as db:
        rows = list(db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(4)))[::-1]
        for prev, cur in zip(rows, rows[1:]):
            assert cur.prev_hash == prev.entry_hash
        assert len(rows[0].entry_hash) == 64


def test_modified_entry_is_detected():
    seed_events()
    target = last_ids(5)[2]
    with SessionLocal() as db:
        assert verify_chain(db)["ok"] is True
        db.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update"))
        db.execute(text("UPDATE audit_log SET detail = 'tampered' WHERE id = :i"), {"i": target})
        result = verify_chain(db)
        db.rollback()  # undo the tampering, including the trigger change
    assert result["ok"] is False and result["first_bad_id"] == target
    with SessionLocal() as db:
        assert verify_chain(db)["ok"] is True


def test_deleted_entry_is_detected():
    seed_events()
    ids = last_ids(5)
    with SessionLocal() as db:
        assert verify_chain(db)["ok"] is True
        db.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update"))
        db.execute(text("DELETE FROM audit_log WHERE id = :i"), {"i": ids[2]})
        result = verify_chain(db)
        db.rollback()
    assert result["ok"] is False and result["first_bad_id"] == ids[3]


@pytest.mark.parametrize(
    "sql",
    ["UPDATE audit_log SET detail = 'x'", "DELETE FROM audit_log", "TRUNCATE audit_log"],
)
def test_database_refuses_to_change_audit_log(sql):
    seed_events(1)
    with SessionLocal() as db:
        with pytest.raises(DBAPIError):
            db.execute(text(sql))
        db.rollback()


def test_concurrent_appends_keep_chain_valid():
    def worker(i: int):
        with SessionLocal() as db:
            log_event(db, "concurrency_test", None, f"worker={i}")

    with SessionLocal() as db:
        before = db.scalar(select(func.count(AuditLog.id)))
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(25)))
    with SessionLocal() as db:
        assert db.scalar(select(func.count(AuditLog.id))) - before == 25
        assert verify_chain(db)["ok"] is True


def test_audit_endpoints_are_admin_only():
    user = Actor()
    assert user.client.get("/audit").status_code == 403
    assert user.client.get("/audit/verify").status_code == 403
    assert TestClient(app).get("/audit").status_code == 401
    admin = Actor()
    set_role(admin.email, "admin")
    r = admin.client.get("/audit/verify")
    assert r.status_code == 200 and r.json()["ok"] is True
    rows = admin.client.get("/audit").json()
    assert 0 < len(rows) <= 100
    assert rows[0]["id"] > rows[-1]["id"]


def test_audit_fails_closed_without_master_key(monkeypatch):
    monkeypatch.setattr(settings, "master_key", "")
    with SessionLocal() as db:
        with pytest.raises(CryptoError):
            log_event(db, "should_not_be_written")
        db.rollback()
