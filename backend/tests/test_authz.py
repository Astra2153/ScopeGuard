import json
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

from app.config import settings
from app.db import SessionLocal
from app.main import app
from app.models import AuditLog, Target, User, utcnow
from app.ratelimit import reset_limits

PASSWORD = "correct-horse-battery-1"
PATH = "/api/orders/{orderId}"
SPEC = {"openapi": "3.0.0", "paths": {
    "/api/orders/{orderId}": {"get": {}},
    "/api/orders": {"get": {}},
    "/api/users/{userId}": {"get": {}},
}}
A = {"authorization": "Bearer alice-token"}
B = {"authorization": "Bearer bob-token"}
IDS = {"orderId": "1001"}


def payload(**over):
    body = {"confirm_authorized": True, "spec": SPEC, "auth_a": A, "auth_b": B, "object_ids": IDS}
    body.update(over)
    return body


@pytest.fixture(autouse=True)
def cleanup_test_users():
    yield
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email.like("%@example.test")))
        db.commit()


class Actor:
    def __init__(self):
        self.client = TestClient(app)
        self.email = f"az_{uuid.uuid4().hex[:12]}@example.test"
        r = self.client.post("/auth/register", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 201
        r = self.client.post("/auth/login", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 200
        self.csrf = r.json()["csrf_token"]

    def call(self, method, url, json=None):
        return self.client.request(method, url, json=json, headers={"X-CSRF-Token": self.csrf})

    def unverified_target(self, srv):
        eng = self.call("POST", "/engagements", {"name": "Acme API"}).json()["id"]
        r = self.call("POST", f"/engagements/{eng}/targets", {"base_url": srv.origin})
        assert r.status_code == 201
        return eng, r.json()

    def verified_target(self, srv):
        eng, t = self.unverified_target(srv)
        srv.token = t["verification_token"]
        assert self.call("POST", f"/targets/{t['id']}/verify").status_code == 200
        return eng, t

    def scan(self, target_id, body=None):
        return self.call("POST", f"/targets/{target_id}/authz-scan", body or payload())

    def findings(self, eng):
        return self.call("GET", f"/engagements/{eng}/findings").json()


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


def outcomes(body):
    return {r["path"]: (r["outcome"], r["anonymous_access"]) for r in body["results"]}


def test_secure_api_produces_no_findings(lab_mode, lab_server):
    a = Actor()
    eng, t = a.verified_target(lab_server)
    r = a.scan(t["id"])
    assert r.status_code == 200
    body = r.json()
    assert outcomes(body) == {PATH: ("denied", False), "/api/users/{userId}": ("skipped_missing_ids", None)}
    assert body["created"] == 0 and body["requests"] == 3 and body["incomplete"] is False
    assert a.findings(eng) == []


def test_bola_is_confirmed(lab_mode, lab_server):
    lab_server.httpd.authz_mode = "bola"
    a = Actor()
    eng, t = a.verified_target(lab_server)
    body = a.scan(t["id"]).json()
    assert outcomes(body)[PATH] == ("confirmed_bola", False)
    assert body["created"] == 1 and body["requests"] == 4
    finding = a.findings(eng)[0]
    assert finding["title"] == "Broken object level authorization: GET /api/orders/{orderId}"
    assert finding["severity"] == "high" and finding["source"] == "authz"


def test_anonymous_access_is_confirmed(lab_mode, lab_server):
    lab_server.httpd.authz_mode = "anon"
    a = Actor()
    eng, t = a.verified_target(lab_server)
    body = a.scan(t["id"]).json()
    assert outcomes(body)[PATH] == ("confirmed_bola", True)
    titles = sorted(f["title"] for f in a.findings(eng))
    assert titles == [
        "Broken object level authorization: GET /api/orders/{orderId}",
        "Endpoint reachable without authentication: GET /api/orders/{orderId}",
    ]


def test_catch_all_endpoint_is_inconclusive_not_a_false_positive(lab_mode, lab_server):
    lab_server.httpd.authz_mode = "catchall"  # returns the same page for every id and identity
    a = Actor()
    eng, t = a.verified_target(lab_server)
    body = a.scan(t["id"]).json()
    assert outcomes(body)[PATH] == ("inconclusive_catch_all", False)
    assert body["created"] == 0 and a.findings(eng) == []


def test_rescan_does_not_duplicate_findings(lab_mode, lab_server):
    lab_server.httpd.authz_mode = "bola"
    a = Actor()
    eng, t = a.verified_target(lab_server)
    a.scan(t["id"])
    second = a.scan(t["id"]).json()
    assert second["created"] == 0 and second["unchanged"] == 1
    assert len(a.findings(eng)) == 1


def test_retest_flow_fix_is_not_auto_closed_and_regression_reopens(lab_mode, lab_server):
    lab_server.httpd.authz_mode = "bola"
    a = Actor()
    eng, t = a.verified_target(lab_server)
    a.scan(t["id"])
    fid = a.findings(eng)[0]["id"]
    assert a.call("PATCH", f"/findings/{fid}", {"status": "fixed"}).status_code == 200
    lab_server.httpd.authz_mode = "secure"  # the client deploys the fix
    after_fix = a.scan(t["id"]).json()
    assert after_fix["created"] == after_fix["reopened"] == after_fix["unchanged"] == 0
    assert a.call("GET", f"/findings/{fid}").json()["status"] == "fixed"
    lab_server.httpd.authz_mode = "bola"  # a regression brings the flaw back
    regression = a.scan(t["id"]).json()
    assert regression["reopened"] == 1
    assert a.call("GET", f"/findings/{fid}").json()["status"] == "not_fixed"


def test_credentials_are_used_but_never_stored_or_echoed(lab_mode, lab_server):
    lab_server.httpd.authz_mode = "bola"
    a = Actor()
    eng, t = a.verified_target(lab_server)
    start = max_audit_id()
    r = a.scan(t["id"])
    seen = [entry[1] for entry in lab_server.httpd.auth_seen]
    assert "Bearer alice-token" in seen and "Bearer bob-token" in seen  # sent to the target
    blob = r.text + json.dumps(a.findings(eng)) + " ".join(e.detail for e in events_since(start))
    assert "alice-token" not in blob and "bob-token" not in blob
    assert "Bearer" not in blob


def test_authorization_confirmation_is_required(lab_mode, lab_server):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    before = len(lab_server.hits)
    missing = payload()
    del missing["confirm_authorized"]
    assert a.scan(t["id"], missing).status_code == 422
    assert a.scan(t["id"], payload(confirm_authorized=False)).status_code == 422
    assert len(lab_server.hits) == before


def test_bad_input_is_rejected_before_any_request(lab_mode, lab_server):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    before = len(lab_server.hits)
    assert a.scan(t["id"], payload(auth_a={"authorization": "Bearer x\r\nX-Evil: 1"})).status_code == 422
    assert a.scan(t["id"], payload(auth_a={"x-api-key": "k"})).status_code == 422
    assert a.scan(t["id"], payload(auth_b=A)).status_code == 422  # both identities are the same
    assert a.scan(t["id"], payload(object_ids={"orderId": "../etc"})).status_code == 422
    assert a.scan(t["id"], payload(spec={"paths": {"/x": {"get": {}}}})).status_code == 422
    assert a.scan(t["id"], payload(extra_field=1)).status_code == 422
    assert len(lab_server.hits) == before


def test_unverified_target_is_refused_without_traffic(lab_mode, lab_server):
    a = Actor()
    _eng, t = a.unverified_target(lab_server)
    r = a.scan(t["id"])
    assert r.status_code == 409 and r.json()["detail"] == "Target is not verified"
    assert lab_server.hits == []


def test_stale_verification_is_refused(lab_mode, lab_server):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    with SessionLocal() as db:
        db.get(Target, uuid.UUID(t["id"])).verified_at = utcnow() - timedelta(days=31)
        db.commit()
    before = len(lab_server.hits)
    assert a.scan(t["id"]).status_code == 409
    assert len(lab_server.hits) == before


def test_policy_is_rechecked_at_scan_time(lab_mode, lab_server, monkeypatch):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    before = len(lab_server.hits)
    monkeypatch.setattr(settings, "allow_private_targets", False)
    r = a.scan(t["id"])
    assert r.status_code == 400 and r.json()["detail"] == "Scan failed: target_not_allowed"
    assert len(lab_server.hits) == before


def test_other_users_and_roles_are_blocked(lab_mode, lab_server):
    a, b = Actor(), Actor()
    _eng, t = a.verified_target(lab_server)
    before = len(lab_server.hits)
    assert b.scan(t["id"]).status_code == 404
    assert TestClient(app).post(f"/targets/{t['id']}/authz-scan", json=payload()).status_code == 401
    assert a.client.post(f"/targets/{t['id']}/authz-scan", json=payload()).status_code == 403  # no CSRF
    set_role(a.email, "client_viewer")
    assert a.scan(t["id"]).status_code == 403
    assert len(lab_server.hits) == before


def test_endpoint_and_request_budgets(lab_mode, lab_server):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    spec = {"paths": {f"/api/r{i}/{{orderId}}": {"get": {}} for i in range(30)}}
    body = a.scan(t["id"], payload(spec=spec)).json()
    assert len(body["results"]) == 20 and body["requests"] <= 80 and body["incomplete"] is True
    assert {r["outcome"] for r in body["results"]} == {"baseline_failed"}


def test_authz_events_are_audited_with_counts_only(lab_mode, lab_server):
    lab_server.httpd.authz_mode = "bola"
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    start = max_audit_id()
    a.scan(t["id"])
    rows = events_since(start)
    assert [r.action for r in rows] == ["authz_scan_started", "authz_scan_finished"]
    assert "authorization_confirmed=true" in rows[0].detail
    assert "confirmed=1" in rows[1].detail
    blob = " ".join(r.detail for r in rows)
    assert "/api/orders" not in blob and lab_server.origin not in blob


def test_authz_scan_is_rate_limited(lab_mode, lab_server, monkeypatch):
    a = Actor()
    _eng, t = a.verified_target(lab_server)
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    reset_limits()
    assert [a.scan(t["id"]).status_code for _ in range(2)] == [200, 200]
    assert a.scan(t["id"]).status_code == 429
