"""
SSH audit — pulls the SSH banner and flags:
    - Old / known-vulnerable OpenSSH versions
    - Non-SSHv2 banners
    - Banner-only fingerprinting that aids attackers

A deeper audit (algorithm negotiation, weak host keys, password auth
permitted) needs paramiko or `ssh-audit` and is a follow-up plugin.
"""
from __future__ import annotations

import re
import socket
from typing import List, Tuple

from . import Finding, NetworkPlugin

_SSH_PORTS = {22, 2222, 22000}
_BANNER_RE = re.compile(r"SSH-(\d)\.(\d)-(.+)")

# Coarse known-bad OpenSSH thresholds. Refined matching is a job for the
# CVE-lookup phase; this list catches the obvious "still on Trusty" hosts.
_OPENSSH_MINIMUM_SAFE = (8, 0)


def _grab_banner(target_ip: str, port: int, timeout: float) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        data = sock.recv(256)
        sock.close()
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _parse_openssh(banner_software: str) -> Tuple[int, int]:
    match = re.search(r"OpenSSH_(\d+)\.(\d+)", banner_software)
    if not match:
        return (-1, -1)
    return (int(match.group(1)), int(match.group(2)))


def _openssh_software_dict(banner_software: str) -> Optional[dict]:
    """Pull a structured OpenSSH version (e.g. 6.6.1p1) for CVE lookup."""
    full = re.search(r"OpenSSH_(\d+\.\d+(?:\.\d+)?p?\d*)", banner_software)
    if not full:
        return None
    return {"name": "openssh", "version": full.group(1)}


def run(target_ip: str, open_ports: List[dict], timeout: float = 3.0) -> List[Finding]:
    findings: List[Finding] = []

    for entry in open_ports:
        port = entry["port"]
        if port not in _SSH_PORTS:
            continue

        banner = _grab_banner(target_ip, port, timeout)
        if not banner:
            continue

        match = _BANNER_RE.match(banner)
        if not match:
            findings.append(
                Finding(
                    plugin="ssh_audit",
                    title=f"Non-SSH service responding on port {port}",
                    severity="LOW",
                    description=f"Port {port} returned: {banner!r}",
                    recommendation="Confirm the service running on this port is intended.",
                    port=port,
                    service="ssh",
                )
            )
            continue

        major, minor, software = match.group(1), match.group(2), match.group(3)
        if major != "2":
            findings.append(
                Finding(
                    plugin="ssh_audit",
                    title=f"SSH protocol version {major}.{minor} on port {port}",
                    severity="HIGH",
                    description=(
                        f"Server advertises SSH-{major}.{minor}. Only SSH-2 is "
                        f"considered secure; SSH-1 is broken."
                    ),
                    recommendation="Disable SSH-1; allow only SSH-2.",
                    port=port,
                    service="ssh",
                    tags=["weak-ssh"],
                )
            )

        ssh_major, ssh_minor = _parse_openssh(software)
        if ssh_major >= 0:
            if (ssh_major, ssh_minor) < _OPENSSH_MINIMUM_SAFE:
                findings.append(
                    Finding(
                        plugin="ssh_audit",
                        title=f"Outdated OpenSSH version on port {port}",
                        severity="MEDIUM",
                        description=(
                            f"OpenSSH version {ssh_major}.{ssh_minor} detected "
                            f"(banner: {software}). Older versions have known "
                            f"vulnerabilities (e.g. user enumeration, MaxAuthTries bypass)."
                        ),
                        recommendation=(
                            "Upgrade to the latest OpenSSH release for the platform."
                        ),
                        port=port,
                        service="ssh",
                        tags=["outdated-software"],
                    )
                )

        findings.append(
            Finding(
                plugin="ssh_audit",
                title=f"SSH banner discloses software on port {port}",
                severity="LOW",
                description=f"Banner: {banner}",
                recommendation=(
                    "Set DebianBanner no in sshd_config (Debian/Ubuntu) and "
                    "consider Banner /etc/issue.net to replace the version "
                    "string with neutral text."
                ),
                port=port,
                service="ssh",
                tags=["info-disclosure"],
                software=_openssh_software_dict(software),
            )
        )

    return findings


PLUGIN = NetworkPlugin(
    name="ssh_audit",
    description="Banner-based SSH version detection and version-too-old flagging",
    runner=run,
)
