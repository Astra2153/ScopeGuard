from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_ok_and_security_headers():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
