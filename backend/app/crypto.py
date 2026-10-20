import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings


class CryptoError(Exception):
    pass


def _subkey(label: bytes) -> bytes:
    """Derive separate keys for separate jobs from the one master key (key separation)."""
    if not settings.master_key:
        raise CryptoError("MASTER_KEY is not configured")  # fail closed
    master = base64.b64decode(settings.master_key)
    if len(master) != 32:
        raise CryptoError("MASTER_KEY must decode to 32 bytes")
    return hmac.new(master, label, hashlib.sha256).digest()


def encrypt(plaintext: str, aad: str) -> str:
    """AES-256-GCM. A fresh random 96-bit nonce per message; aad binds it to its owner."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(_subkey(b"aes-256-gcm")).encrypt(nonce, plaintext.encode(), aad.encode())
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt(token: str, aad: str) -> str:
    try:
        data = base64.b64decode(token)
        plain = AESGCM(_subkey(b"aes-256-gcm")).decrypt(data[:12], data[12:], aad.encode())
        return plain.decode()
    except CryptoError:
        raise
    except Exception as exc:  # tampered data, wrong aad, wrong key: all look the same
        raise CryptoError("decryption failed") from exc


def keyed_hash(value: str) -> str:
    """HMAC-SHA256 with a server-side key: stolen hashes cannot be brute-forced without the key."""
    return hmac.new(_subkey(b"hmac-sha256"), value.encode(), hashlib.sha256).hexdigest()


from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _signing_key() -> Ed25519PrivateKey:
    # The seed is derived from the master key with its own label (key separation).
    return Ed25519PrivateKey.from_private_bytes(_subkey(b"ed25519-signing"))


def public_key_bytes() -> bytes:
    return _signing_key().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def public_key_b64() -> str:
    return base64.b64encode(public_key_bytes()).decode()


def key_id() -> str:
    """Short fingerprint of the public key, so a report says which key signed it."""
    return hashlib.sha256(public_key_bytes()).hexdigest()[:16]


def sign_bytes(data: bytes) -> str:
    return base64.b64encode(_signing_key().sign(data)).decode()


def verify_signature(data: bytes, signature_b64: str, public_key: bytes | None = None) -> bool:
    try:
        key = (
            Ed25519PublicKey.from_public_bytes(public_key)
            if public_key
            else _signing_key().public_key()
        )
        key.verify(base64.b64decode(signature_b64, validate=True), data)
        return True
    except (InvalidSignature, ValueError):
        return False
