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
