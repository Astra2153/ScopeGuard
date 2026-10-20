import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# argon2-cffi's PasswordHasher uses Argon2id by default, with a random salt per hash.
_ph = PasswordHasher()

# Used to spend the same hashing time when the email does not exist.
DUMMY_HASH = _ph.hash("dummy-password-for-timing-only")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _ph.check_needs_rehash(stored_hash)


def new_token() -> str:
    """Random 256-bit token from the OS CSPRNG."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Session tokens are high-entropy, so a fast SHA-256 is appropriate (unlike passwords)."""
    return hashlib.sha256(token.encode()).hexdigest()


def safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
