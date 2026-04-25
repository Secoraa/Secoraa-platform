"""
Network scanner plugins.

Each plugin implements a `run(target_ip, open_ports, timeout) -> list[Finding]`
contract. Findings are dataclass instances that the orchestrator converts to
Vulnerability rows.

Adding a new plugin:
    1. Create a module here that exports `PLUGIN` (a NetworkPlugin instance).
    2. Register it in the `ALL_PLUGINS` list at the bottom of this file.
    3. Run a network scan — the orchestrator will pick it up.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class Finding:
    """A single network-layer finding emitted by a plugin."""

    plugin: str
    title: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
    description: str
    recommendation: str
    port: Optional[int] = None
    service: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    reference: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class NetworkPlugin:
    """Plugin descriptor — a name plus the runner function."""

    name: str
    description: str
    runner: Callable[[str, List[dict], float], List[Finding]]


from .extended_ports import PLUGIN as EXTENDED_PORTS
from .banner_grab import PLUGIN as BANNER_GRAB
from .http_service import PLUGIN as HTTP_SERVICE
from .tls_audit import PLUGIN as TLS_AUDIT
from .ssh_audit import PLUGIN as SSH_AUDIT
from .ftp_anonymous import PLUGIN as FTP_ANONYMOUS
from .dns_misconfig import PLUGIN as DNS_MISCONFIG
from .exposed_db import PLUGIN as EXPOSED_DB

ALL_PLUGINS: List[NetworkPlugin] = [
    EXTENDED_PORTS,
    BANNER_GRAB,
    HTTP_SERVICE,
    TLS_AUDIT,
    SSH_AUDIT,
    FTP_ANONYMOUS,
    DNS_MISCONFIG,
    EXPOSED_DB,
]
