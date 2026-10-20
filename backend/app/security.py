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
