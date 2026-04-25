"""
Banner grabber — connects to each open TCP port, optionally sends a small
protocol-appropriate hello, reads what comes back. Banners often disclose
software + version, which lets later plugins (or a future CVE-lookup phase)
match known vulnerabilities.
"""
from __future__ import annotations

import re
import socket
from typing import List, Optional

from . import Finding, NetworkPlugin

# Light protocol nudges so the server actually says something.
_PROBES: dict = {
    21: b"",                       # FTP greets you on connect
    22: b"",                       # SSH greets you on connect
    23: b"",                       # Telnet greets you on connect
    25: b"EHLO secoraa.scan\r\n",  # SMTP
    80: b"GET / HTTP/1.0\r\nHost: scan\r\nUser-Agent: Secoraa\r\n\r\n",
    110: b"",                      # POP3 greets
    143: b". CAPABILITY\r\n",      # IMAP
    8080: b"GET / HTTP/1.0\r\nHost: scan\r\nUser-Agent: Secoraa\r\n\r\n",
}

_VERSION_PATTERNS = [
    re.compile(rb"Server: ([^\r\n]+)", re.IGNORECASE),
    re.compile(rb"SSH-\d\.\d-([^\r\n]+)"),
    re.compile(rb"^220 ([^\r\n]+)", re.MULTILINE),    # FTP / SMTP
    re.compile(rb"^\+OK ([^\r\n]+)", re.MULTILINE),   # POP3
]


def _grab(target_ip: str, port: int, timeout: float) -> Optional[bytes]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        probe = _PROBES.get(port, b"")
        if probe:
            sock.sendall(probe)
        data = sock.recv(2048)
        sock.close()
        return data or None
    except Exception:
        return None


def _extract_version(banner: bytes) -> Optional[str]:
    for pattern in _VERSION_PATTERNS:
        match = pattern.search(banner)
        if match:
            return match.group(1).decode("utf-8", errors="replace").strip()
    return None


def run(target_ip: str, open_ports: List[dict], timeout: float = 2.0) -> List[Finding]:
    findings: List[Finding] = []

    for entry in open_ports:
        port = entry["port"]
        service = entry.get("service", "?")
        banner = _grab(target_ip, port, timeout)
        if not banner:
            continue

        version = _extract_version(banner)
        snippet = banner[:200].decode("utf-8", errors="replace").strip()

        if version:
            findings.append(
                Finding(
                    plugin="banner_grab",
                    title=f"Service version disclosed on port {port}",
                    severity="LOW",
                    description=(
                        f"Port {port} ({service}) responded with software "
                        f"version: {version}. Version disclosure helps "
                        f"attackers map the host to known CVEs."
                    ),
                    recommendation=(
                        "Configure the service to suppress version banners. "
                        "Examples: nginx `server_tokens off`, Apache "
                        "`ServerTokens Prod`, OpenSSH 'DebianBanner no'."
                    ),
                    port=port,
                    service=service,
                    tags=["info-disclosure", "fingerprintable"],
                )
            )
        else:
            findings.append(
                Finding(
                    plugin="banner_grab",
                    title=f"Service banner captured on port {port}",
                    severity="INFORMATIONAL",
                    description=f"Port {port} returned: {snippet!r}",
                    recommendation="No action required if the banner does not include version data.",
                    port=port,
                    service=service,
                )
            )

    return findings


PLUGIN = NetworkPlugin(
    name="banner_grab",
    description="Connects to each open TCP port and captures any banner / version string",
    runner=run,
)
