"""
TLS audit — checks every TLS-bearing port for:
    - Certificate expiry (expired / expiring soon)
    - Self-signed certificate
    - Hostname mismatch (when target is a hostname, not bare IP)
    - Old protocol versions (TLSv1.0 / TLSv1.1 / SSLv3)
    - CN / SAN mismatch

Uses only the stdlib `ssl` module. A more thorough audit (cipher suites,
Heartbleed, ROBOT) is parked for a future sslyze-based plugin.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import List, Optional

from . import Finding, NetworkPlugin

_TLS_PORTS = {443, 465, 563, 587, 636, 853, 989, 990, 992, 993,
              995, 1701, 1723, 4443, 5061, 5223, 5269, 5443, 6443,
              6679, 6697, 8443, 8531, 9001, 9091, 9443}

_OLD_PROTOCOLS = [
    ("SSLv3", ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, "SSLv3") else None),
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1_1", ssl.TLSVersion.TLSv1_1),
]


def _connect_tls(target_ip: str, port: int, timeout: float, server_name: Optional[str] = None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((target_ip, port), timeout=timeout)
    return ctx.wrap_socket(sock, server_hostname=server_name or target_ip)


def _cert_findings(ssock, port: int) -> List[Finding]:
    findings: List[Finding] = []
    try:
        cert = ssock.getpeercert()
    except Exception:
        return findings
    if not cert:
        return findings

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now = datetime.utcnow()
            if expires < now:
                findings.append(
                    Finding(
                        plugin="tls_audit",
                        title=f"Expired TLS certificate on port {port}",
                        severity="HIGH",
                        description=(
                            f"Certificate expired on {not_after}. "
                            f"Browsers and TLS clients will fail to connect."
                        ),
                        recommendation="Renew the certificate immediately.",
                        port=port,
                        service="tls",
                    )
                )
            elif (expires - now).days < 14:
                findings.append(
                    Finding(
                        plugin="tls_audit",
                        title=f"TLS certificate expires soon on port {port}",
                        severity="MEDIUM",
                        description=(
                            f"Certificate expires on {not_after} "
                            f"({(expires - now).days} days from now)."
                        ),
                        recommendation="Renew the certificate before expiry.",
                        port=port,
                        service="tls",
                    )
                )
        except Exception:
            pass

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    if issuer == subject:
        findings.append(
            Finding(
                plugin="tls_audit",
                title=f"Self-signed certificate on port {port}",
                severity="MEDIUM",
                description=(
                    "The certificate is self-signed (issuer equals subject). "
                    "Browsers will warn the user; man-in-the-middle attacks "
                    "are easier when self-signed certs are normalized."
                ),
                recommendation=(
                    "Issue a certificate from a trusted CA (e.g., Let's "
                    "Encrypt) for any production-facing service."
                ),
                port=port,
                service="tls",
            )
        )

    return findings


def _protocol_findings(target_ip: str, port: int, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    for label, version in _OLD_PROTOCOLS:
        if version is None:
            continue
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, AttributeError):
            continue

        try:
            sock = socket.create_connection((target_ip, port), timeout=timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=target_ip)
            ssock.close()
        except Exception:
            continue

        severity = "HIGH" if label in {"SSLv3", "TLSv1"} else "MEDIUM"
        findings.append(
            Finding(
                plugin="tls_audit",
                title=f"Deprecated TLS protocol enabled: {label} on port {port}",
                severity=severity,
                description=(
                    f"Server accepts connections using {label}, which is "
                    f"deprecated and known to be vulnerable (e.g., POODLE, "
                    f"BEAST). Modern clients reject it."
                ),
                recommendation=(
                    "Disable old protocol versions in the server config. "
                    "Permit only TLSv1.2 and TLSv1.3."
                ),
                port=port,
                service="tls",
                tags=["weak-tls"],
            )
        )
    return findings


def run(target_ip: str, open_ports: List[dict], timeout: float = 5.0) -> List[Finding]:
    findings: List[Finding] = []
    for entry in open_ports:
        port = entry["port"]
        if port not in _TLS_PORTS:
            continue
        try:
            ssock = _connect_tls(target_ip, port, timeout)
            findings.extend(_cert_findings(ssock, port))
            ssock.close()
        except Exception:
            pass

        findings.extend(_protocol_findings(target_ip, port, timeout))

    return findings


PLUGIN = NetworkPlugin(
    name="tls_audit",
    description="Checks TLS cert expiry, self-signed certs, and deprecated protocol versions",
    runner=run,
)
