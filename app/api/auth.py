from __future__ import annotations

import os
import logging
import base64
import hmac
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.database.models import User
from app.database.session import get_db


router = APIRouter(prefix="/auth", tags=["Auth"])

security = HTTPBearer(auto_error=True)
ph = PasswordHasher()
logger = logging.getLogger(__name__)


class TokenExpired(Exception):
    pass


class TokenInvalid(Exception):
    pass


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("utf-8"))


def _jwt_encode(payload: Dict[str, Any], secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _jwt_decode(token: str, secret: str) -> Dict[str, Any]:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except Exception:
        raise TokenInvalid("Malformed token")

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    expected_sig_b64 = _b64url_encode(expected_sig)

    if not hmac.compare_digest(expected_sig_b64, sig_b64):
        raise TokenInvalid("Bad signature")

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        raise TokenInvalid("Invalid payload")

    now = int(datetime.now(timezone.utc).timestamp())
    exp = payload.get("exp")
    if isinstance(exp, int) and exp < now:
        raise TokenExpired("Token expired")

    return payload


def _jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        # Require explicit secret so local and production behave the same.
        raise RuntimeError("JWT_SECRET is not set. Set it in environment (recommended) or in .env.")
    return secret


def _jwt_exp_minutes() -> int:
    try:
        return int(os.getenv("JWT_EXPIRES_MINUTES", "240"))
    except Exception:
        return 240


def _issue_token(*, username: str, tenant: str, auth_details: Dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": username,
        "tenant": tenant,
        "auth": auth_details,  # "authentication details"
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=_jwt_exp_minutes())).timestamp()),
        "iss": "secoraa-backend",
    }
    return _jwt_encode(payload, _jwt_secret())


def _decode_token(token: str) -> Dict[str, Any]:
    return _jwt_decode(token, _jwt_secret())


def _verify_env_credentials(username: str, password: str) -> None:
    """
    Minimal credential check for now (no frontend requested).
    Configure via env:
    - AUTH_USERNAME
    - AUTH_PASSWORD
    """
    exp_user = os.getenv("AUTH_USERNAME", "")
    exp_pass = os.getenv("AUTH_PASSWORD", "")

    if not exp_user or not exp_pass:
        raise HTTPException(
            status_code=500,
            detail="Auth is not configured. Set AUTH_USERNAME and AUTH_PASSWORD in environment.",
        )

    if username != exp_user or password != exp_pass:
        raise HTTPException(status_code=401, detail="Invalid username or password")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenClaimsResponse(BaseModel):
    sub: str
    tenant: str
    auth: Dict[str, Any]
    iat: int
    exp: int
    iss: Optional[str] = None


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    try:
        # 1) Prefer DB-backed auth (signup/onboarding)
        user = db.query(User).filter(User.username == body.username).first()
        if user:
            if not getattr(user, "is_active", True):
                raise HTTPException(status_code=403, detail="User is inactive")
            try:
                ph.verify(user.password_hash, body.password)
            except VerifyMismatchError:
                raise HTTPException(status_code=401, detail="Invalid username or password")
            tenant = getattr(user, "tenant", None) or os.getenv("AUTH_TENANT", "default")
        else:
            # 2) Fallback to env-based auth (optional)
            _verify_env_credentials(body.username, body.password)
            tenant = os.getenv("AUTH_TENANT", "default")

        auth_details = {
            "username": body.username,
            "login_method": "password",
        }
        token = _issue_token(username=body.username, tenant=tenant, auth_details=auth_details)
        return TokenResponse(
            access_token=token,
            token_type="bearer",
            expires_in=_jwt_exp_minutes() * 60,
        )
    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class SignupRequest(BaseModel):
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=8)
    tenant: Optional[str] = Field(default=None, description="Company name (tenant)")


@router.post("/signup")
def signup(body: SignupRequest, db: Session = Depends(get_db)):
    """
    Onboard a user (create username + password).
    Password is hashed (argon2) and stored in DB.
    """
    try:
        tenant = (body.tenant or os.getenv("AUTH_TENANT") or "default").strip()
        if not tenant:
            tenant = "default"

        user = User(
            username=body.username.strip(),
            password_hash=ph.hash(body.password),
            tenant=tenant,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return {
            "id": str(user.id),
            "username": user.username,
            "tenant": user.tenant,
            "is_active": user.is_active,
            "created_at": user.created_at,
        }
    except ProgrammingError as e:
        # e.g. (psycopg2.errors.UndefinedTable) relation "users" does not exist
        try:
            db.rollback()
        except Exception:
            pass
        raise HTTPException(
            status_code=400,
            detail=(
                "Database table 'users' does not exist yet. "
                "Run: python app/scripts/create_tables.py (or your DB migration) and try again. "
                f"Error: {str(e)}"
            ),
        )
    except IntegrityError:
        try:
            db.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=409, detail="User already exists")
    except HTTPException:
        raise
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=str(e))


def get_token_claims(
    creds: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    """
    Dependency to enforce: Authorization: Bearer <TOKEN>
    """
    token = creds.credentials
    try:
        return _decode_token(token)
    except TokenExpired:
        raise HTTPException(status_code=401, detail="Token expired")
    except TokenInvalid:
        raise HTTPException(status_code=401, detail="Invalid token")
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/token", response_model=TokenClaimsResponse)
def get_token(claims: Dict[str, Any] = Depends(get_token_claims)) -> TokenClaimsResponse:
    """
    "Get token" endpoint: validate the bearer token and return its claims.
    """
    return TokenClaimsResponse(
        sub=str(claims.get("sub", "")),
        tenant=str(claims.get("tenant", "")),
        auth=dict(claims.get("auth") or {}),
        iat=int(claims.get("iat") or 0),
        exp=int(claims.get("exp") or 0),
        iss=claims.get("iss"),
    )

