import base64
import time
import uuid

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.crypto import CryptoError, decrypt, encrypt, keyed_hash
from app.db import SessionLocal
from app.main import app
from app.models import BackupCode, User

PASSWORD = "correct-horse-battery-1"
GENERIC = {"detail": "Invalid email or password"}


@pytest.fixture(autouse=True)
def cleanup_test_users():
    yield
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email.like("%@example.test")))
        db.commit()


class Actor:
    def __init__(self):
        self.client = TestClient(app)
        self.email = f"m_{uuid.uuid4().hex[:12]}@example.test"
        r = self.client.post("/auth/register", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 201
        self.id = r.json()["id"]
        r = self.client.post("/auth/login", json={"email": self.email, "password": PASSWORD})
        assert r.status_code == 200
        self.csrf = r.json()["csrf_token"]

    def call(self, method, url, json=None):
        return self.client.request(method, url, json=json, headers={"X-CSRF-Token": self.csrf})


def enable_mfa(a: Actor):
    r = a.call("POST", "/auth/mfa/setup")
    assert r.status_code == 200
    secret = r.json()["secret"]
    totp = pyotp.TOTP(secret)
    r = a.call("POST", "/auth/mfa/enable", {"code": totp.now()})
    assert r.status_code == 200
    return secret, totp, r.json()["backup_codes"]


def fresh_login(email, otp=None):
    c = TestClient(app)
    body = {"email": email, "password": PASSWORD}
    if otp is not None:
        body["otp"] = otp
    return c.post("/auth/login", json=body)


def wrong_code(totp):
    now = time.time()
    valid = {totp.at(now + d) for d in (-30, 0, 30)}
    return next(c for c in ("000000", "111111", "222222") if c not in valid)


def db_user(email):
    with SessionLocal() as db:
        return db.scalar(select(User).where(User.email == email))


def test_encrypt_roundtrip_and_random_nonce():
    a = encrypt("topsecret", "user-1")
    b = encrypt("topsecret", "user-1")
    assert a != b  # fresh random nonce each time
    assert decrypt(a, "user-1") == "topsecret"
    assert "topsecret" not in a


def test_tampered_ciphertext_detected():
    raw = bytearray(base64.b64decode(encrypt("topsecret", "user-1")))
    raw[-1] ^= 1
    with pytest.raises(CryptoError):
        decrypt(base64.b64encode(bytes(raw)).decode(), "user-1")


def test_ciphertext_bound_to_its_owner():
    token = encrypt("topsecret", "user-1")
    with pytest.raises(CryptoError):
        decrypt(token, "user-2")


def test_setup_stores_secret_encrypted_not_enabled_yet():
    a = Actor()
    r = a.call("POST", "/auth/mfa/setup")
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/")
    user = db_user(a.email)
    assert user.mfa_enabled is False
    assert user.mfa_secret and secret not in user.mfa_secret
    assert decrypt(user.mfa_secret, str(user.id)) == secret


def test_enable_with_wrong_code_rejected():
    a = Actor()
    secret = a.call("POST", "/auth/mfa/setup").json()["secret"]
    r = a.call("POST", "/auth/mfa/enable", {"code": wrong_code(pyotp.TOTP(secret))})
    assert r.status_code == 400
    assert db_user(a.email).mfa_enabled is False


def test_enable_returns_backup_codes_stored_only_as_keyed_hashes():
    a = Actor()
    _secret, _totp, codes = enable_mfa(a)
    assert len(codes) == 8 and len(set(codes)) == 8
    with SessionLocal() as db:
        stored = {row.code_hash for row in db.scalars(select(BackupCode).where(BackupCode.user_id == uuid.UUID(a.id)))}
    assert len(stored) == 8
    for code in codes:
        raw = code.replace("-", "")
        assert raw not in stored and code not in stored
        assert keyed_hash(raw) in stored


def test_login_needs_otp_after_mfa_enabled():
    a = Actor()
    _secret, totp, _codes = enable_mfa(a)
    missing = fresh_login(a.email)
    assert missing.status_code == 401 and missing.json() == {"detail": "MFA code required"}
    wrong = fresh_login(a.email, wrong_code(totp))
    assert wrong.status_code == 401 and wrong.json() == GENERIC
    ok = fresh_login(a.email, totp.at(time.time() + 30))
    assert ok.status_code == 200


def test_totp_code_cannot_be_replayed():
    a = Actor()
    _secret, totp, _codes = enable_mfa(a)
    code = totp.at(time.time() + 30)
    assert fresh_login(a.email, code).status_code == 200
    assert fresh_login(a.email, code).status_code == 401


def test_backup_code_works_exactly_once():
    a = Actor()
    _secret, _totp, codes = enable_mfa(a)
    assert fresh_login(a.email, codes[0]).status_code == 200
    assert fresh_login(a.email, codes[0]).status_code == 401
    # Formatting is forgiving: no dash, upper case.
    assert fresh_login(a.email, codes[1].replace("-", "").upper()).status_code == 200


def test_wrong_otps_trigger_lockout():
    a = Actor()
    _secret, totp, codes = enable_mfa(a)
    for _ in range(5):
        r = fresh_login(a.email, wrong_code(totp))
        assert r.status_code == 401 and r.json() == GENERIC
    locked = fresh_login(a.email, codes[0])  # a valid backup code is refused while locked
    assert locked.status_code == 401 and locked.json() == GENERIC


def test_mfa_endpoints_need_login_and_csrf():
    anon = TestClient(app)
    assert anon.post("/auth/mfa/setup").status_code == 401
    a = Actor()
    assert a.client.post("/auth/mfa/setup").status_code == 403


def test_disable_needs_password_and_code():
    a = Actor()
    _secret, _totp, codes = enable_mfa(a)
    bad = a.call("POST", "/auth/mfa/disable", {"password": "not-the-password-1", "code": codes[0]})
    assert bad.status_code == 401
    assert db_user(a.email).mfa_enabled is True
    ok = a.call("POST", "/auth/mfa/disable", {"password": PASSWORD, "code": codes[0]})
    assert ok.status_code == 204
    user = db_user(a.email)
    assert user.mfa_enabled is False and user.mfa_secret is None
    assert fresh_login(a.email).status_code == 200  # no OTP needed any more


def test_setup_again_after_enable_is_refused():
    a = Actor()
    enable_mfa(a)
    assert a.call("POST", "/auth/mfa/setup").status_code == 409
