"""Verify a ScopeGuard report offline.

Usage: python verify_report.py REPORT.md SIGNATURE_BASE64 PUBLIC_KEY_BASE64
Exit code: 0 = valid, 1 = invalid, 2 = wrong usage.
"""
import base64
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 2
    path, signature_b64, public_key_b64 = argv[1:]
    try:
        with open(path, "rb") as handle:
            data = handle.read()
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        key.verify(base64.b64decode(signature_b64, validate=True), data)
    except (InvalidSignature, ValueError, OSError):
        print("INVALID")
        return 1
    print("VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
