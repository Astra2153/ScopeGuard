import base64
import hashlib
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

from app.config import settings
from app.crypto import CryptoError
from app.db import SessionLocal
from app.main import app
from app.models import AuditLog, Report, User
from app.ratelimit import reset_limits
from app.reportgen import md_block, md_escape

PASSWORD = "correct-horse-battery-1"
VERIFY_SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "verify_report.py"
EXPECTED_H2 = {"## Scope", "## Summary", "## Findings", "## Method and limits"}


@pytest.fixture(autouse=True)
def cleanup_test_users():
    yield
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email.like("%@example.test")))
        db.commit()


class Actor:
    def __init__(self):
        self.client = TestClient(app)
        self.email = f"rp_{uuid.uuid4().hex[:12]}@example.test"
        r = self.client.post("/auth/register", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 201
        r = self.client.post("/auth/login", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 200
        self.csrf = r.json()["csrf_token"]

    def call(self, method, url, json=None):
        return self.client.request(method, url, json=json, headers={"X-CSRF-Token": self.csrf})

    def make_engagement(self, name="Acme Payments API"):
        r = self.call("POST", "/engagements", {"name": name})
        assert r.status_code == 201
        return r.json()["id"]

    def add_finding(self, eng, title, severity="low", description=""):
        r = self.call(
            "POST", f"/engagements/{eng}/findings",
            {"title": title, "severity": severity, "description": description},
        )
        assert r.status_code == 201
        return r.json()["id"]

    def create_report(self, eng):
        r = self.call("POST", f"/engagements/{eng}/reports")
        assert r.status_code == 201, r.text
        return r.json()

    def content(self, rid):
        return self.call("GET", f"/reports/{rid}").json()["content"]


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


def test_md_escape_and_block_neutralise_markdown():
    assert md_escape("a\n# b") == "a \\# b"
    assert "](" not in md_escape("[x](javascript:alert(1))")
    assert "<" not in md_escape("<script>alert(1)</script>").replace("\\<", "")
    assert md_escape("evil\u202etext\u200b") == "eviltext"
    assert len(md_escape("x" * 1000)) == 300
    quoted = md_block("line1\n# Heading\n![i](http://x/y.png)")
    assert all(line.startswith(">") for line in quoted.splitlines())
    assert "](" not in quoted and "\n# " not in quoted


def test_report_content_and_summary():
    a = Actor()
    eng = a.make_engagement("Acme Payments API")
    a.add_finding(eng, "Missing CSP", "low")
    a.add_finding(eng, "IDOR in orders", "high", "Users can read other orders.")
    rid = a.create_report(eng)["id"]
    content = a.content(rid)
    assert content.startswith("# Security Assessment Report")
    assert "Acme Payments API" in content
    assert content.index("IDOR in orders") < content.index("Missing CSP")  # high before low
    assert "Users can read other orders" in content
    assert "| high | 1 | 1 |" in content and "| low | 1 | 1 |" in content
    assert a.email not in content  # user IDs only, never emails


def test_empty_engagement_report():
    a = Actor()
    rid = a.create_report(a.make_engagement())["id"]
    content = a.content(rid)
    assert "No findings were recorded." in content
    assert "No targets were registered" in content


def test_reports_are_point_in_time_snapshots():
    a = Actor()
    eng = a.make_engagement()
    fid = a.add_finding(eng, "Missing CSP", "low")
    first = a.create_report(eng)["id"]
    assert a.call("PATCH", f"/findings/{fid}", {"status": "fixed"}).status_code == 200
    second = a.create_report(eng)["id"]
    assert "| low | 1 | 1 |" in a.content(first)  # the old snapshot is unchanged
    assert "| low | 1 | 0 |" in a.content(second)
    ids = [r["id"] for r in a.call("GET", f"/engagements/{eng}/reports").json()]
    assert ids == [second, first]  # newest first


def unescaped(content: str, chars: str) -> list[str]:
    """Characters from `chars` that no backslash protects, ignoring the report's own '> ' block-quote marker."""
    bad = []
    for line in content.splitlines():
        if line.startswith("> "):
            line = line[2:]
        elif line == ">":
            line = ""
        for i, ch in enumerate(line):
            if ch in chars and (i == 0 or line[i - 1] != "\\"):
                bad.append(line[max(0, i - 15): i + 15])
    return bad


def test_malicious_finding_text_cannot_inject_markdown_or_html():
    import re

    a = Actor()
    eng = a.make_engagement()
    a.add_finding(
        eng,
        "[click](javascript:alert(1)) <script>alert(1)</script>\n# Fake heading\u202e",
        "high",
        "line1\n# Injected heading\n![img](http://evil.test/x.png)\n<img src=x onerror=alert(1)>",
    )
    rid = a.create_report(eng)["id"]
    content = a.content(rid)
    lines = content.splitlines()
    # The text is still there, but every markup character is escaped, so a renderer shows it literally.
    assert "\\<script\\>alert\\(1\\)\\</script\\>" in content
    assert "\\[click\\]\\(javascript:alert\\(1\\)\\)" in content
    # No unescaped angle bracket anywhere (the report's own block-quote markers are excluded).
    assert unescaped(content, "<>") == []
    # No unescaped markdown link anywhere: a "](" that no backslash protects.
    assert re.search(r"(?<!\\)\]\(", content) is None
    assert "\u202e" not in content
    # Structure cannot be forged: one H1, the known H2 sections, and exactly one finding heading.
    assert [ln for ln in lines if ln.startswith("# ")] == ["# Security Assessment Report"]
    assert {ln for ln in lines if ln.startswith("## ")} == EXPECTED_H2
    assert len([ln for ln in lines if ln.startswith("### ")]) == 1
    assert not any(ln.startswith("![") for ln in lines)
    # Description lines stay inside block quotes, including the ones that looked like headings.
    assert all(ln.startswith(">") for ln in lines if "Injected heading" in ln or "evil.test" in ln)

def test_signature_verifies_with_the_public_key_independently():
    a = Actor()
    rid = a.create_report(a.make_engagement())["id"]
    pub = a.client.get("/reports/public-key").json()
    download = a.client.get(f"/reports/{rid}/download")
    assert download.status_code == 200
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub["public_key"]))
    signature = base64.b64decode(download.headers["x-report-signature"])
    key.verify(signature, download.content)  # raises if invalid
    assert download.headers["x-report-key-id"] == pub["key_id"]
    with pytest.raises(InvalidSignature):
        key.verify(signature, download.content + b"x")


def test_download_headers_are_safe_and_audited():
    a = Actor()
    rid = a.create_report(a.make_engagement())["id"]
    start = max_audit_id()
    r = a.client.get(f"/reports/{rid}/download")
    assert r.headers["content-type"].startswith("text/markdown")
    assert r.headers["content-disposition"] == f'attachment; filename="scopeguard-report-{rid}.md"'
    assert r.headers["x-content-type-options"] == "nosniff"
    sig = a.call("GET", f"/reports/{rid}/signature").json()
    assert sig["sha256"] == hashlib.sha256(r.content).hexdigest()
    assert [e.action for e in events_since(start)] == ["report_downloaded"]


def test_public_key_is_public_and_stable():
    anon = TestClient(app)
    first = anon.get("/reports/public-key")
    second = anon.get("/reports/public-key")
    assert first.status_code == 200 and first.json() == second.json()
    assert len(first.json()["key_id"]) == 16 and first.json()["algorithm"] == "Ed25519"


def test_stored_report_tampering_is_detected():
    a = Actor()
    rid = a.create_report(a.make_engagement())["id"]
    good = a.call("GET", f"/reports/{rid}/verify").json()
    assert good == {
        "valid": True, "sha256_matches": True, "signature_valid": True, "signed_with_current_key": True,
    }
    with SessionLocal() as db:
        row = db.get(Report, uuid.UUID(rid))
        row.content = row.content + "\nforged line"
        db.commit()
    bad = a.call("GET", f"/reports/{rid}/verify").json()
    assert bad["valid"] is False and bad["sha256_matches"] is False and bad["signature_valid"] is False


def test_offline_script_verifies_and_rejects(tmp_path):
    a = Actor()
    rid = a.create_report(a.make_engagement())["id"]
    pub = a.client.get("/reports/public-key").json()["public_key"]
    download = a.client.get(f"/reports/{rid}/download")
    sig = download.headers["x-report-signature"]
    report = tmp_path / "report.md"
    report.write_bytes(download.content)

    def run(*args):
        return subprocess.run([sys.executable, str(VERIFY_SCRIPT), *args], capture_output=True, text=True)

    ok = run(str(report), sig, pub)
    assert ok.returncode == 0 and "VALID" in ok.stdout and "INVALID" not in ok.stdout
    report.write_bytes(download.content.replace(b"Security", b"Secur1ty", 1))
    bad = run(str(report), sig, pub)
    assert bad.returncode == 1 and "INVALID" in bad.stdout
    assert run(str(report)).returncode == 2


def test_report_signing_fails_closed_without_the_key(monkeypatch):
    a = Actor()
    eng = a.make_engagement()
    monkeypatch.setattr(settings, "master_key", "")
    with pytest.raises(CryptoError):
        a.call("POST", f"/engagements/{eng}/reports")
    monkeypatch.undo()
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Report.id)).where(Report.engagement_id == uuid.UUID(eng))) == 0


def test_user_b_cannot_touch_user_a_reports():
    a, b = Actor(), Actor()
    eng = a.make_engagement()
    rid = a.create_report(eng)["id"]
    assert b.call("POST", f"/engagements/{eng}/reports").status_code == 404
    assert b.call("GET", f"/engagements/{eng}/reports").status_code == 404
    for suffix in ("", "/download", "/signature", "/verify"):
        assert b.call("GET", f"/reports/{rid}{suffix}").status_code == 404, suffix
    assert a.call("GET", f"/reports/{rid}/verify").json()["valid"] is True


def test_authentication_and_csrf_required():
    a = Actor()
    eng = a.make_engagement()
    rid = a.create_report(eng)["id"]
    anon = TestClient(app)
    assert anon.post(f"/engagements/{eng}/reports").status_code == 401
    assert anon.get(f"/engagements/{eng}/reports").status_code == 401
    for suffix in ("", "/download", "/signature", "/verify"):
        assert anon.get(f"/reports/{rid}{suffix}").status_code == 401, suffix
    assert a.client.post(f"/engagements/{eng}/reports").status_code == 403  # no CSRF header


def test_roles_viewer_reads_but_cannot_create_and_admin_reads_all():
    a, admin = Actor(), Actor()
    eng = a.make_engagement()
    rid = a.create_report(eng)["id"]
    set_role(admin.email, "admin")
    assert admin.call("GET", f"/reports/{rid}").status_code == 200
    set_role(a.email, "client_viewer")
    assert a.call("GET", f"/reports/{rid}").status_code == 200
    assert a.call("POST", f"/engagements/{eng}/reports").status_code == 403


def test_reports_are_immutable_through_the_api():
    a = Actor()
    rid = a.create_report(a.make_engagement())["id"]
    assert a.call("PATCH", f"/reports/{rid}", {"content": "x"}).status_code == 405
    assert a.call("PUT", f"/reports/{rid}", {"content": "x"}).status_code == 405
    assert a.call("DELETE", f"/reports/{rid}").status_code == 405


def test_deleting_an_engagement_removes_its_reports():
    a = Actor()
    eng = a.make_engagement()
    rid = a.create_report(eng)["id"]
    assert a.call("DELETE", f"/engagements/{eng}").status_code == 204
    assert a.call("GET", f"/reports/{rid}").status_code == 404


def test_creation_is_audited_with_ids_only():
    a = Actor()
    eng = a.make_engagement("Secret client name")
    a.add_finding(eng, "Secret finding title")
    start = max_audit_id()
    rid = a.create_report(eng)["id"]
    rows = events_since(start)
    assert [r.action for r in rows] == ["report_created"]
    assert rows[0].detail == f"report={rid} engagement={eng}"
    assert "Secret" not in rows[0].detail


def test_report_creation_is_rate_limited(monkeypatch):
    a = Actor()
    eng = a.make_engagement()
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    reset_limits()
    assert [a.call("POST", f"/engagements/{eng}/reports").status_code for _ in range(5)] == [201] * 5
    assert a.call("POST", f"/engagements/{eng}/reports").status_code == 429


