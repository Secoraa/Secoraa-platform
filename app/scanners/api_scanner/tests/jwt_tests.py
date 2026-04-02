from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import struct
import time
from typing import Any, Dict, List, Optional

from app.scanners.api_scanner.engine.request_executor import execute_request
from app.scanners.api_scanner.tests import make_finding

logger = logging.getLogger(__name__)

OWASP = "API2:2023"
REF = "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"

# Common weak secrets for HS256 brute-force
WEAK_SECRETS = [
    "secret", "password", "123456", "12345678", "admin", "test",
    "key", "jwt_secret", "changeme", "default", "letmein",
    "abc123", "qwerty", "1234567890", "jwt", "token",
]

# Sensitive fields that shouldn't be in JWT payload
SENSITIVE_FIELDS = {
    "password", "passwd", "secret", "ssn", "credit_card", "cc_number",
    "card_number", "cvv", "private_key", "api_secret", "db_password",
}


def _b64decode_jwt(segment: str) -> Optional[Dict]:
    """Base64url-decode a JWT segment and return parsed JSON."""
    try:
        padding = 4 - len(segment) % 4
        segment += "=" * padding
        decoded = base64.urlsafe_b64decode(segment)
        return json.loads(decoded)
    except Exception:
        return None


def _b64encode_jwt(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _build_alg_none_token(header: Dict, payload: Dict) -> str:
    """Build a JWT with alg=none and empty signature."""
    new_header = {**header, "alg": "none"}
    h = _b64encode_jwt(json.dumps(new_header, separators=(",", ":")).encode())
    p = _b64encode_jwt(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def _sign_hs256(header: Dict, payload: Dict, secret: str) -> str:
    """Sign a JWT with HS256 and a given secret."""
    new_header = {**header, "alg": "HS256"}
    h = _b64encode_jwt(json.dumps(new_header, separators=(",", ":")).encode())
    p = _b64encode_jwt(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64encode_jwt(sig)}"


async def run_jwt_tests(
    token: str,
    test_url: str,
    auth_headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    """
    Run JWT-specific security tests. This is a GLOBAL check — run once per scan
    when a Bearer JWT token is provided.
    """
    findings: List[Dict[str, Any]] = []

    parts = token.split(".")
    if len(parts) != 3:
        return findings  # Not a JWT

    header = _b64decode_jwt(parts[0])
    payload = _b64decode_jwt(parts[1])

    if not header or not payload:
        return findings

    alg = header.get("alg", "")
    ep_label = f"JWT Analysis"

    # ── 1. alg:none bypass ────────────────────────────────────────────
    none_token = _build_alg_none_token(header, payload)
    none_headers = {"Authorization": f"Bearer {none_token}"}
    resp, evidence = await execute_request("GET", test_url, headers=none_headers)
    if resp is not None and resp.status_code == 200 and len(resp.text or "") > 2:
        findings.append(make_finding(
            owasp_category=OWASP,
            title="JWT Algorithm None Bypass",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            endpoint=ep_label,
            description="The API accepts JWT tokens with 'alg: none' (no signature). Any user can forge tokens.",
            evidence=evidence,
            impact="Complete authentication bypass. Any attacker can forge valid JWT tokens for any user.",
            remediation="Reject tokens with alg=none. Enforce a specific algorithm (e.g., RS256) server-side. Never trust the alg header from the client.",
            references=[REF],
        ))

    # ── 2. Weak secret (HS256 brute-force) ────────────────────────────
    if alg in ("HS256", "HS384", "HS512"):
        for secret in WEAK_SECRETS:
            test_token = _sign_hs256(header, payload, secret)
            test_headers = {"Authorization": f"Bearer {test_token}"}
            resp, evidence = await execute_request("GET", test_url, headers=test_headers)
            if resp is not None and resp.status_code == 200 and len(resp.text or "") > 2:
                findings.append(make_finding(
                    owasp_category=OWASP,
                    title=f"JWT Weak Signing Secret: '{secret}'",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    endpoint=ep_label,
                    description=f"The JWT signing secret is the weak/common value '{secret}'. Tokens can be forged by anyone.",
                    evidence=evidence,
                    impact="Complete authentication bypass. Attacker can sign tokens for any user using the known weak secret.",
                    remediation="Use a cryptographically random secret of at least 256 bits. Consider switching to asymmetric algorithms (RS256) where the signing key is never shared.",
                    references=[REF],
                ))
                break  # One proof is enough

    # ── 3. Missing or weak expiry ─────────────────────────────────────
    exp = payload.get("exp")
    iat = payload.get("iat")

    if exp is None:
        findings.append(make_finding(
            owasp_category=OWASP,
            title="JWT Missing Expiration Claim",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            endpoint=ep_label,
            description="The JWT token has no 'exp' (expiration) claim. The token never expires.",
            evidence={"request": {}, "response": {"jwt_payload": {k: v for k, v in payload.items() if k not in SENSITIVE_FIELDS}}},
            impact="Stolen tokens remain valid forever. There is no way to revoke access without changing the signing key.",
            remediation="Always include an 'exp' claim in JWT tokens. Set a reasonable expiry (e.g., 1 hour for access tokens, 7 days for refresh tokens).",
            references=[REF],
        ))
    elif iat and (exp - iat) > 86400:  # More than 24 hours
        lifetime_hours = (exp - iat) / 3600
        findings.append(make_finding(
            owasp_category=OWASP,
            title="JWT Excessively Long Expiry",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
            endpoint=ep_label,
            description=f"The JWT token has a lifetime of {lifetime_hours:.0f} hours (>24h). Long-lived tokens increase the window for token theft exploitation.",
            evidence={"request": {}, "response": {"jwt_iat": iat, "jwt_exp": exp, "lifetime_hours": round(lifetime_hours, 1)}},
            impact="If a token is stolen, the attacker has an extended window to use it before it expires.",
            remediation="Set access token expiry to 1 hour or less. Use refresh tokens for longer sessions.",
            confidence="MEDIUM",
            references=[REF],
        ))

    # ── 4. Expired token still accepted ───────────────────────────────
    if exp and exp < time.time():
        # Token is already expired — test if the API still accepts it
        resp, evidence = await execute_request("GET", test_url, headers=auth_headers)
        if resp is not None and resp.status_code == 200 and len(resp.text or "") > 2:
            findings.append(make_finding(
                owasp_category=OWASP,
                title="Expired JWT Token Still Accepted",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                endpoint=ep_label,
                description="The API accepts an expired JWT token. Token expiration is not enforced server-side.",
                evidence=evidence,
                impact="Token revocation and expiration are meaningless. Stolen tokens work indefinitely.",
                remediation="Validate the 'exp' claim server-side on every request. Reject expired tokens with 401.",
                references=[REF],
            ))

    # ── 5. Sensitive data in payload ──────────────────────────────────
    exposed_fields = [k for k in payload if k.lower() in SENSITIVE_FIELDS]
    if exposed_fields:
        findings.append(make_finding(
            owasp_category=OWASP,
            title="Sensitive Data in JWT Payload",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            endpoint=ep_label,
            description=f"The JWT payload contains sensitive fields: {', '.join(exposed_fields)}. JWT payloads are base64-encoded (NOT encrypted) and readable by anyone.",
            evidence={"request": {}, "response": {"exposed_fields": exposed_fields}},
            impact="Sensitive data (passwords, secrets, PII) is exposed to anyone who intercepts or decodes the token.",
            remediation="Never store sensitive data in JWT payloads. JWTs are signed, not encrypted. Store only non-sensitive identifiers (user ID, role).",
            confidence="HIGH",
            references=[REF],
        ))

    return findings
