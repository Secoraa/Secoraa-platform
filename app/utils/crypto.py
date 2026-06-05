from __future__ import annotations

import base64
import os
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def _derive_key() -> bytes:
    secret = os.getenv("JWT_SECRET") or os.getenv("SECRET_KEY") or "insecure-default-change-me"
    raw = secret.encode("utf-8")
    return (raw * 4)[:32]


def encrypt_field(plaintext: Optional[str]) -> Optional[str]:
    """AES-256-GCM encrypt a string. Returns base64-encoded blob prefixed with 'enc:'."""
    if not plaintext:
        return plaintext
    key = _derive_key()
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return "enc:" + base64.b64encode(nonce + tag + ciphertext).decode()


def decrypt_field(value: Optional[str]) -> Optional[str]:
    """Decrypt a value from encrypt_field. Returns plaintext; passes through unencrypted values."""
    if not value:
        return value
    if not value.startswith("enc:"):
        return value  # legacy plaintext — return as-is
    try:
        raw = base64.b64decode(value[4:])
        nonce, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
        cipher = AES.new(_derive_key(), AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
    except Exception:
        return value  # corrupted blob — return raw rather than crash
