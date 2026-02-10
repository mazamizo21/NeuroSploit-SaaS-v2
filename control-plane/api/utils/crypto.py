"""
Lightweight symmetric obfuscation for storing secrets at rest.

Note: This is NOT strong encryption. It is a reversible obfuscation intended
for low-risk storage in dev/test environments. Use a KMS/Vault in production.
"""

from __future__ import annotations

import base64
import hashlib
import os

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")


def _derive_key() -> bytes:
    return hashlib.sha256(SECRET_KEY.encode()).digest()


def encrypt_value(value: str) -> str:
    """Obfuscate a secret value for storage."""
    if value is None:
        raise ValueError("value must not be None")
    key_bytes = _derive_key()
    raw = value.encode()
    encrypted = bytes(
        a ^ b for a, b in zip(raw, (key_bytes * (len(raw) // 32 + 1))[: len(raw)])
    )
    return base64.b64encode(encrypted).decode()


def decrypt_value(encrypted: str) -> str:
    """Reverse obfuscation for a stored secret."""
    if encrypted is None:
        raise ValueError("encrypted must not be None")
    key_bytes = _derive_key()
    decoded = base64.b64decode(encrypted)
    decrypted = bytes(
        a ^ b for a, b in zip(decoded, (key_bytes * (len(decoded) // 32 + 1))[: len(decoded)])
    )
    return decrypted.decode()


def mask_value(value: str) -> str:
    """Show only last 4 chars of a secret value."""
    if not value:
        return "****"
    if len(value) <= 4:
        return "****"
    return "•" * (len(value) - 4) + value[-4:]
