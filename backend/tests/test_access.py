import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, inspect, select

from app.db import SessionLocal, engine
from app.main import app
from app.models import User

PASSWORD = "correct-horse-battery-1"


@pytest.fixture(autouse=True)
def cleanup_test_users():
    yield
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email.like("%@example.test")))
        db.commit()


class Actor:
    """A registered, logged-in user with its own cookie jar."""

    def __init__(self):
        self.client = TestClient(app)
        self.email = f"a_{uuid.uuid4().hex[:12]}@example.test"
        r = self.client.post("/auth/register", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 201
        self.id = r.json()["id"]
        r = self.client.post("/auth/login", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 200
        self.csrf = r.json()["csrf_token"]

    def call(self, method, url, json=None):
        return self.client.request(method, url, json=json, headers={"X-CSRF-Token": self.csrf})

    def make_engagement(self, name="Acme API"):
        r = self.call("POST", "/engagements", {"name": name})
        assert r.status_code == 201
        return r.json()["id"]

    def make_finding(self, eng_id, title="IDOR in /orders"):
        r = self.call("POST", f"/engagements/{eng_id}/findings", {"title": title, "severity": "high"})
        assert r.status_code == 201
        return r.json()["id"]


def set_role(email: str, role: str):
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        user.role = role
        db.commit()


def endpoint_matrix(eng_id: str, finding_id: str):
    """Every endpoint that touches one specific engagement or finding."""
    return [
        ("GET", f"/engagements/{eng_id}", None),
        ("DELETE", f"/engagements/{eng_id}", None),
        ("GET", f"/engagements/{eng_id}/findings", None),
        ("POST", f"/engagements/{eng_id}/findings", {"title": "x"}),
        ("GET", f"/findings/{finding_id}", None),
        ("PATCH", f"/findings/{finding_id}", {"status": "fixed"}),
        ("DELETE", f"/findings/{finding_id}", None),
    ]


def test_unauthenticated_requests_rejected():
    anon = TestClient(app)
    for method, url, body in endpoint_matrix(str(uuid.uuid4()), str(uuid.uuid4())):
        assert anon.request(method, url, json=body).status_code == 401, (method, url)
    assert anon.get("/engagements").status_code == 401
    assert anon.post("/engagements", json={"name": "x"}).status_code == 401


def test_owner_can_create_list_get_delete():
    a = Actor()
    eng_id = a.make_engagement()
    assert eng_id in [e["id"] for e in a.call("GET", "/engagements").json()]
    assert a.call("GET", f"/engagements/{eng_id}").status_code == 200
    f_id = a.make_finding(eng_id)
    assert len(a.call("GET", f"/engagements/{eng_id}/findings").json()) == 1
    assert a.call("DELETE", f"/findings/{f_id}").status_code == 204
    assert a.call("GET", f"/findings/{f_id}").status_code == 404
    assert a.call("DELETE", f"/engagements/{eng_id}").status_code == 204
    assert a.call("GET", f"/engagements/{eng_id}").status_code == 404


def test_user_b_cannot_touch_user_a_resources():
    a, b = Actor(), Actor()
    eng_id = a.make_engagement()
    f_id = a.make_finding(eng_id)
    for method, url, body in endpoint_matrix(eng_id, f_id):
        r = b.call(method, url, body)
        assert r.status_code == 404, (method, url, r.status_code)
    # A's data is completely untouched.
    assert a.call("GET", f"/engagements/{eng_id}").status_code == 200
    finding = a.call("GET", f"/findings/{f_id}").json()
    assert finding["status"] == "open"
    assert len(a.call("GET", f"/engagements/{eng_id}/findings").json()) == 1


def test_list_only_shows_own_engagements():
    a, b = Actor(), Actor()
    a_id = a.make_engagement("A only")
    b_id = b.make_engagement("B only")
    a_ids = [e["id"] for e in a.call("GET", "/engagements").json()]
    b_ids = [e["id"] for e in b.call("GET", "/engagements").json()]
    assert a_id in a_ids and b_id not in a_ids
    assert b_id in b_ids and a_id not in b_ids


def test_admin_can_read_any_engagement():
    a, admin = Actor(), Actor()
    set_role(admin.email, "admin")
    eng_id = a.make_engagement()
    assert admin.call("GET", f"/engagements/{eng_id}").status_code == 200


def test_client_viewer_cannot_create():
    v = Actor()
    set_role(v.email, "client_viewer")
    assert v.call("POST", "/engagements", {"name": "x"}).status_code == 403


def test_writes_require_csrf():
    a = Actor()
    eng_id = a.make_engagement()
    assert a.client.post("/engagements", json={"name": "x"}).status_code == 403
    assert a.client.delete(f"/engagements/{eng_id}").status_code == 403
    assert a.call("GET", f"/engagements/{eng_id}").status_code == 200  # still exists


def test_mass_assignment_rejected():
    a, b = Actor(), Actor()
    r = a.call("POST", "/engagements", {"name": "x", "owner_id": b.id})
    assert r.status_code == 422


def test_invalid_severity_rejected():
    a = Actor()
    eng_id = a.make_engagement()
    r = a.call("POST", f"/engagements/{eng_id}/findings", {"title": "x", "severity": "catastrophic"})
    assert r.status_code == 422


def test_finding_status_update_and_invalid_status():
    a = Actor()
    f_id = a.make_finding(a.make_engagement())
    assert a.call("PATCH", f"/findings/{f_id}", {"status": "fixed"}).json()["status"] == "fixed"
    assert a.call("PATCH", f"/findings/{f_id}", {"status": "hacked"}).status_code == 422


def test_injection_style_text_is_stored_as_data():
    a = Actor()
    eng_id = a.make_engagement()
    nasty = "x'); DROP TABLE users;--"
    a.make_finding(eng_id, title=nasty)
    titles = [f["title"] for f in a.call("GET", f"/engagements/{eng_id}/findings").json()]
    assert titles == [nasty]  # returned literally, never executed
    assert "users" in inspect(engine).get_table_names()
