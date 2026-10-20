import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

from app.checks import CORS_PROBE_ORIGIN
from app.config import settings
from app.db import SessionLocal
from app.main import app
from app.models import AuditLog, Target, User, utcnow
from app.ratelimit import reset_limits

PASSWORD = "correct-horse-battery-1"
PLAIN_HTTP = "Target is served over plain HTTP"
SECURE_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Set-Cookie", "sid=abc; Path=/; HttpOnly; SameSite=Lax"),
]


@pytest.fixture(autouse=True)
def cleanup_test_users():
    yield
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email.like("%@example.test")))
        db.commit()


class Actor:
    def __init__(self):
        self.client = TestClient(app)
        self.email = f"sc_{uuid.uuid4().hex[:12]}@example.test"
        r = self.client.post("/auth/register", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 201
        r = self.client.post("/auth/login", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 200
        self.csrf = r.json()["csrf_token"]

    def call(self, method, url, json=None):
        return self.client.request(method, url, json=json, headers={"X-CSRF-Token": self.csrf})

    def unverified_target(self, srv):
        r = self.call("POST", "/engagements", {"name": "Acme API"})
        eng = r.json()["id"]
        r = self.call("POST", f"/engagements/{eng}/targets", {"base_url": srv.origin})
        assert r.status_code == 201
        return eng, r.json()

    def verified_target(self, srv):
        eng, t = self.unverified_target(srv)
        srv.token = t["verification_token"]
        assert self.call("POST", f"/targets/{t['id']}/verify").status_code == 200
        return eng, t

    def findings(self, eng):
        return self.call("GET", f"/engagements/{eng}/findings").json()

    def titles(self, eng):
        return sorted(f["title"] for f in self.findings(eng))


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


def test_scan_refused_for_unverified_target(lab_mode, lab_server):
    a = Actor()
    _eng, t = a.unverified_target(lab_server)
    r = a.call("POST", f"/targets/{t['id']}/scan")
    assert r.status_code == 409 and r.json()["detail"] == "Target is not verified"
    assert lab_server.hits == []  # nothing was sent to the target


def test_scan_refused_when_verification_is_stale(lab_mode, lab_server):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    with SessionLocal() as db:
        target = db.get(Target, uuid.UUID(t["id"]))
        target.verified_at = utcnow() - timedelta(days=31)
        db.commit()
    before = len(lab_server.hits)
    assert a.call("POST", f"/targets/{t['id']}/scan").status_code == 409
    assert len(lab_server.hits) == before


def test_scan_reports_findings_as_scanner_source(lab_mode, lab_server):
    lab_server.httpd.root_headers = [("Server", "nginx/1.18.0"), ("Set-Cookie", "sid=abc123; Path=/")]
    a = Actor()
    eng, t = a.verified_target(lab_server)
    r = a.call("POST", f"/targets/{t['id']}/scan")
    assert r.status_code == 200
    body = r.json()
    assert body["created"] >= 8 and body["reopened"] == 0 and body["incomplete"] is False
    titles = a.titles(eng)
    for expected in (
        PLAIN_HTTP,
        "Missing Content-Security-Policy header",
        "Missing X-Content-Type-Options header",
        "Server header discloses version information",
        "Cookie 'sid' missing HttpOnly flag",
        "Cookie 'sid' missing SameSite attribute",
    ):
        assert expected in titles
    assert all(f["source"] == "scanner" for f in a.findings(eng))


def test_well_configured_target_has_no_false_positives(lab_mode, lab_server):
    lab_server.httpd.root_headers = list(SECURE_HEADERS)
    a = Actor()
    eng, t = a.verified_target(lab_server)
    assert a.call("POST", f"/targets/{t['id']}/scan").status_code == 200
    assert a.titles(eng) == [PLAIN_HTTP]  # only the genuine issue: the lab server is plain HTTP


def test_rescan_does_not_duplicate_findings(lab_mode, lab_server):
    a = Actor()
    eng, t = a.verified_target(lab_server)
    first = a.call("POST", f"/targets/{t['id']}/scan").json()
    count = len(a.findings(eng))
    second = a.call("POST", f"/targets/{t['id']}/scan").json()
    assert second["created"] == 0 and second["unchanged"] == first["created"]
    assert len(a.findings(eng)) == count


def test_finding_marked_fixed_reopens_if_still_present(lab_mode, lab_server):
    a = Actor()
    eng, t = a.verified_target(lab_server)
    a.call("POST", f"/targets/{t['id']}/scan")
    csp = next(f for f in a.findings(eng) if f["title"] == "Missing Content-Security-Policy header")
    assert a.call("PATCH", f"/findings/{csp['id']}", {"status": "fixed"}).status_code == 200
    r = a.call("POST", f"/targets/{t['id']}/scan").json()
    assert r["reopened"] == 1
    assert a.call("GET", f"/findings/{csp['id']}").json()["status"] == "not_fixed"


def test_cors_reflection_with_credentials_detected(lab_mode, lab_server):
    lab_server.httpd.cors_reflect = True
    a = Actor()
    eng, t = a.verified_target(lab_server)
    a.call("POST", f"/targets/{t['id']}/scan")
    cors = [f for f in a.findings(eng) if f["title"].startswith("CORS reflects any origin")]
    assert len(cors) == 1 and cors[0]["severity"] == "high"
    assert CORS_PROBE_ORIGIN in lab_server.httpd.origins_seen


def test_exposed_files_detected_but_contents_never_stored(lab_mode, lab_server):
    lab_server.httpd.exposed = {"git", "env"}
    a = Actor()
    eng, t = a.verified_target(lab_server)
    a.call("POST", f"/targets/{t['id']}/scan")
    titles = a.titles(eng)
    assert "Exposed Git repository metadata (/.git/HEAD)" in titles
    assert "Exposed environment file (/.env)" in titles
    blob = " ".join(f["title"] + f["description"] for f in a.findings(eng))
    assert "hunter2" not in blob and "DB_PASSWORD" not in blob and "abc123" not in blob


def test_scan_is_get_only_and_small(lab_mode, lab_server):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    before = len(lab_server.hits)
    body = a.call("POST", f"/targets/{t['id']}/scan").json()
    new = lab_server.hits[before:]
    assert {h[0] for h in new} == {"GET"}
    assert len(new) == body["requests"] <= 8


def test_policy_is_rechecked_at_scan_time(lab_mode, lab_server, monkeypatch):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    before = len(lab_server.hits)
    monkeypatch.setattr(settings, "allow_private_targets", False)
    r = a.call("POST", f"/targets/{t['id']}/scan")
    assert r.status_code == 400 and r.json()["detail"] == "Scan failed: target_not_allowed"
    assert len(lab_server.hits) == before


def test_unreachable_target_reported(lab_mode, lab_server):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    lab_server.stop()
    r = a.call("POST", f"/targets/{t['id']}/scan")
    assert r.status_code == 400 and r.json()["detail"] == "Scan failed: target_unreachable"


def test_other_users_cannot_scan(lab_mode, lab_server):
    a, b = Actor(), Actor()
    _eng, t = a.verified_target(lab_server)
    before = len(lab_server.hits)
    assert b.call("POST", f"/targets/{t['id']}/scan").status_code == 404
    assert len(lab_server.hits) == before


def test_scan_needs_login_csrf_and_a_writer_role(lab_mode, lab_server):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    assert TestClient(app).post(f"/targets/{t['id']}/scan").status_code == 401
    assert a.client.post(f"/targets/{t['id']}/scan").status_code == 403
    set_role(a.email, "client_viewer")
    assert a.call("POST", f"/targets/{t['id']}/scan").status_code == 403


def test_scan_events_are_audited_with_ids_and_counts_only(lab_mode, lab_server):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    start = max_audit_id()
    a.call("POST", f"/targets/{t['id']}/scan")
    rows = events_since(start)
    assert [r.action for r in rows] == ["scan_started", "scan_finished"]
    assert "created=" in rows[1].detail and "requests=" in rows[1].detail
    blob = " ".join(r.detail for r in rows)
    assert lab_server.origin not in blob and "Missing" not in blob


def test_scan_is_rate_limited(lab_mode, lab_server, monkeypatch):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    reset_limits()
    assert [a.call("POST", f"/targets/{t['id']}/scan").status_code for _ in range(3)] == [200] * 3
    assert a.call("POST", f"/targets/{t['id']}/scan").status_code == 429
