from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.orm import Session

from app.database.models import EmailOtpCode, User

logger = logging.getLogger(__name__)

ph = PasswordHasher()

OTP_TTL_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
RESEND_COOLDOWN_SECONDS = 60


def _generate_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def issue_otp(db: Session, user: User, purpose: str) -> str:
    """
    Invalidate any outstanding codes for this (user, purpose), issue a new
    6-digit code, and return it in plaintext to the caller (for emailing).
    """
    now = datetime.utcnow()
    (
        db.query(EmailOtpCode)
        .filter(
            EmailOtpCode.user_id == user.id,
            EmailOtpCode.purpose == purpose,
            EmailOtpCode.used_at.is_(None),
        )
        .update({"used_at": now}, synchronize_session=False)
    )

    code = _generate_code()
    record = EmailOtpCode(
        user_id=user.id,
        purpose=purpose,
        code_hash=ph.hash(code),
        attempts=0,
        expires_at=now + timedelta(minutes=OTP_TTL_MINUTES),
    )
    db.add(record)
    db.commit()
    return code


def latest_active_otp(db: Session, user: User, purpose: str) -> Optional[EmailOtpCode]:
    return (
        db.query(EmailOtpCode)
        .filter(
            EmailOtpCode.user_id == user.id,
            EmailOtpCode.purpose == purpose,
            EmailOtpCode.used_at.is_(None),
        )
        .order_by(EmailOtpCode.created_at.desc())
        .first()
    )


def can_resend(db: Session, user: User, purpose: str) -> tuple[bool, int]:
    """
    Returns (allowed, seconds_to_wait). Blocks a resend if the last issued
    code for this user+purpose was created less than RESEND_COOLDOWN_SECONDS ago.
    """
    latest = latest_active_otp(db, user, purpose)
    if not latest:
        return True, 0
    age = (datetime.utcnow() - latest.created_at).total_seconds()
    if age >= RESEND_COOLDOWN_SECONDS:
        return True, 0
    return False, int(RESEND_COOLDOWN_SECONDS - age)


class OtpError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def verify_otp(db: Session, user: User, purpose: str, submitted_code: str) -> None:
    """
    Verify a submitted 6-digit code. Raises OtpError on any failure. On
    success, marks the OTP record as used.
    """
    submitted_code = (submitted_code or "").strip()
    if not submitted_code.isdigit() or len(submitted_code) != 6:
        raise OtpError("invalid_format", "Enter the 6-digit code from your email.")

    record = latest_active_otp(db, user, purpose)
    if not record:
        raise OtpError("not_found", "No active verification code. Request a new one.")

    if record.expires_at < datetime.utcnow():
        record.used_at = datetime.utcnow()
        db.commit()
        raise OtpError("expired", "This code has expired. Request a new one.")

    if record.attempts >= OTP_MAX_ATTEMPTS:
        record.used_at = datetime.utcnow()
        db.commit()
        raise OtpError("too_many_attempts", "Too many incorrect attempts. Request a new code.")

    try:
        ph.verify(record.code_hash, submitted_code)
    except VerifyMismatchError:
        record.attempts += 1
        db.commit()
        remaining = OTP_MAX_ATTEMPTS - record.attempts
        raise OtpError(
            "mismatch",
            f"Incorrect code. {remaining} attempt(s) remaining." if remaining > 0
            else "Incorrect code. Request a new one.",
        )

    record.used_at = datetime.utcnow()
    db.commit()
