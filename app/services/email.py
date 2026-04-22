from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Optional

logger = logging.getLogger(__name__)


def _smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_FROM"))


def send_email(
    to: str,
    subject: str,
    body_text: str,
    body_html: Optional[str] = None,
) -> bool:
    """
    Send an email via SMTP. If SMTP env vars are not configured, logs the
    message to the console (dev fallback) and returns True so the caller
    doesn't fail in local dev.

    Env vars:
      - SMTP_HOST (required for real delivery)
      - SMTP_PORT (default 587)
      - SMTP_USER (optional)
      - SMTP_PASS (optional)
      - SMTP_FROM (required for real delivery)
      - SMTP_USE_TLS (default "true")
    """
    if not _smtp_configured():
        logger.warning(
            "SMTP not configured — logging email instead of sending.\n"
            "  TO: %s\n  SUBJECT: %s\n  BODY:\n%s",
            to,
            subject,
            body_text,
        )
        return True

    host = os.environ["SMTP_HOST"]
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASS")
    sender = os.environ["SMTP_FROM"]
    use_tls = os.getenv("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes")

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    try:
        if port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as server:
                server.ehlo()
                if user and password:
                    server.login(user, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as server:
                server.ehlo()
                if use_tls:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                if user and password:
                    server.login(user, password)
                server.send_message(msg)
        logger.info("Email sent to %s (subject=%s)", to, subject)
        return True
    except Exception as exc:  # noqa: BLE001 — surface all SMTP errors uniformly
        logger.error("Failed to send email to %s: %s", to, exc)
        return False


def send_signup_otp(to: str, code: str) -> bool:
    subject = "Verify your Secoraa account"
    text = (
        f"Welcome to NEXVEIL!\n\n"
        f"Your verification code is: {code}\n\n"
        f"This code expires in 10 minutes.\n"
        f"If you didn't create an account, you can ignore this email."
    )
    html = f"""
      <div style="font-family: Inter, Arial, sans-serif; color: #1a1721;">
        <h2 style="color: #E0B12B;">Welcome to Secoraa</h2>
        <p>Use the code below to verify your email address.</p>
        <p style="font-size: 28px; letter-spacing: 6px; font-weight: 700;
                  background: #f5f3f7; padding: 12px 16px; border-radius: 8px;
                  display: inline-block;">{code}</p>
        <p style="color: #555;">This code expires in 10 minutes.</p>
        <p style="color: #999; font-size: 12px;">
          If you didn't create an account, you can safely ignore this email.
        </p>
      </div>
    """
    return send_email(to, subject, text, html)


def send_password_reset_otp(to: str, code: str) -> bool:
    subject = "Reset your Secoraa password"
    text = (
        f"We received a request to reset your Secoraa password.\n\n"
        f"Your password reset code is: {code}\n\n"
        f"This code expires in 10 minutes.\n"
        f"If you didn't request a password reset, you can safely ignore this email "
        f"— your password will not be changed."
    )
    html = f"""
      <div style="font-family: Inter, Arial, sans-serif; color: #1a1721;">
        <h2 style="color: #E0B12B;">Reset your password</h2>
        <p>We received a request to reset your Secoraa password. Use the code below to continue.</p>
        <p style="font-size: 28px; letter-spacing: 6px; font-weight: 700;
                  background: #f5f3f7; padding: 12px 16px; border-radius: 8px;
                  display: inline-block;">{code}</p>
        <p style="color: #555;">This code expires in 10 minutes.</p>
        <p style="color: #999; font-size: 12px;">
          If you didn't request a password reset, you can safely ignore this email —
          your password will not be changed.
        </p>
      </div>
    """
    return send_email(to, subject, text, html)
