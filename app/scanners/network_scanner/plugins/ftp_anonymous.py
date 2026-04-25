"""
FTP anonymous-login probe — uses ftplib to attempt the legacy
`anonymous@example.com` login and reports the result.
"""
from __future__ import annotations

import ftplib
from typing import List

from . import Finding, NetworkPlugin

_FTP_PORTS = {21, 2121}


def run(target_ip: str, open_ports: List[dict], timeout: float = 5.0) -> List[Finding]:
    findings: List[Finding] = []
    for entry in open_ports:
        port = entry["port"]
        if port not in _FTP_PORTS:
            continue
        try:
            ftp = ftplib.FTP()
            ftp.connect(target_ip, port, timeout=timeout)
            response = ftp.login("anonymous", "scan@secoraa.io")
            try:
                listing = ftp.nlst()[:10]
            except Exception:
                listing = []
            ftp.quit()

            findings.append(
                Finding(
                    plugin="ftp_anonymous",
                    title=f"FTP anonymous login enabled on port {port}",
                    severity="HIGH",
                    description=(
                        f"Server accepted anonymous credentials. "
                        f"Response: {response}. Top-level entries: {listing}."
                    ),
                    recommendation=(
                        "Disable anonymous access. Configure FTP to require "
                        "authenticated users only, or migrate to SFTP/FTPS."
                    ),
                    port=port,
                    service="ftp",
                    tags=["anonymous-login", "weak-auth"],
                )
            )
        except ftplib.error_perm:
            # Login was rejected — that's the secure outcome.
            continue
        except Exception:
            continue

    return findings


PLUGIN = NetworkPlugin(
    name="ftp_anonymous",
    description="Tests for anonymous FTP login on FTP ports",
    runner=run,
)
