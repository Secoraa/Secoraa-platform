from __future__ import annotations

import base64
import os
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

# Domain separator — changing this invalidates all existing enc:v1: blobs.
# If you ever rotate this, bump the version prefix too.
_HKDF_SALT = b"secoraa-field-encryption-v1"

_V1_PREFIX = "enc:v1:"
_LEGACY_PREFIX = "enc:"


def _get_secret() -> str:
    return os.getenv("JWT_SECRET") or os.getenv("SECRET_KEY") or "insecure-default-change-me"


def _derive_key_v1() -> bytes:
    """HKDF-SHA256 — cryptographically sound key derivation."""
    return HKDF(
        master=_get_secret().encode("utf-8"),
        key_len=32,
        salt=_HKDF_SALT,
        hashmod=SHA256,
    )


def _derive_key_legacy() -> bytes:
    """Original (weak) KDF kept only to decrypt old enc: blobs during migration."""
    raw = _get_secret().encode("utf-8")
    return (raw * 4)[:32]


def _aes_gcm_encrypt(key: bytes, plaintext: str) -> str:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return base64.b64encode(nonce + tag + ciphertext).decode()


def _aes_gcm_decrypt(key: bytes, blob: str) -> Optional[str]:
    raw = base64.b64decode(blob)
    nonce, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


def encrypt_field(plaintext: Optional[str]) -> Optional[str]:
    """AES-256-GCM encrypt using HKDF-derived key. Prefix: enc:v1:"""
    if not plaintext:
        return plaintext
    return _V1_PREFIX + _aes_gcm_encrypt(_derive_key_v1(), plaintext)


def decrypt_field(value: Optional[str]) -> Optional[str]:
    """Decrypt enc:v1: (HKDF) or enc: (legacy). Passes through plaintext."""
    if not value:
        return value
    if value.startswith(_V1_PREFIX):
        try:
            return _aes_gcm_decrypt(_derive_key_v1(), value[len(_V1_PREFIX):])
        except Exception:
            return value  # corrupted — return raw rather than crash
    if value.startswith(_LEGACY_PREFIX):
        try:
            return _aes_gcm_decrypt(_derive_key_legacy(), value[len(_LEGACY_PREFIX):])
        except Exception:
            return value
    return value  # plaintext passthrough
