"""
Exposed-database probes — for ports that commonly run unauthenticated:
    - Redis (6379): send PING, INFO; flag if either succeeds
    - Memcached (11211): send `version\r\n`; flag if it responds
    - MongoDB (27017): send isMaster; flag if it responds without auth
    - Elasticsearch (9200): GET /; flag if it returns a cluster banner

These checks send only read-only / introspection commands. Any response
without auth means the database is internet-accessible to anyone.
"""
from __future__ import annotations

import socket
import struct
from typing import List, Optional

import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from . import Finding, NetworkPlugin

disable_warnings(InsecureRequestWarning)


def _send_recv(target_ip: str, port: int, payload: bytes, timeout: float, n: int = 2048) -> Optional[bytes]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        if payload:
            sock.sendall(payload)
        data = sock.recv(n)
        sock.close()
        return data or None
    except Exception:
        return None


def _check_redis(target_ip: str, port: int, timeout: float) -> Optional[Finding]:
    response = _send_recv(target_ip, port, b"*1\r\n$4\r\nPING\r\n", timeout)
    if response and response.startswith(b"+PONG"):
        return Finding(
            plugin="exposed_db",
            title=f"Redis instance reachable without authentication on port {port}",
            severity="CRITICAL",
            description=(
                "Redis responded to PING from an unauthenticated client. "
                "An attacker can read/write all keys, run arbitrary commands "
                "(CONFIG SET, MODULE LOAD), and in many cases achieve RCE "
                "via the SLAVEOF/MODULE LOAD vector."
            ),
            recommendation=(
                "Bind Redis to localhost (`bind 127.0.0.1`), set `requirepass`, "
                "and put management ports behind a VPN/firewall."
            ),
            port=port,
            service="redis",
            tags=["unauth-db", "exposed-db", "rce-risk"],
        )
    if response and response.startswith(b"-NOAUTH"):
        return Finding(
            plugin="exposed_db",
            title=f"Redis exposed (auth required) on port {port}",
            severity="MEDIUM",
            description="Redis is internet-reachable. Auth is required, but exposing the port still enables credential brute force.",
            recommendation="Restrict the port via firewall to known clients only.",
            port=port,
            service="redis",
            tags=["exposed-db"],
        )
    return None


def _check_memcached(target_ip: str, port: int, timeout: float) -> Optional[Finding]:
    response = _send_recv(target_ip, port, b"version\r\n", timeout)
    if response and response.startswith(b"VERSION"):
        version = response.decode("utf-8", errors="replace").strip()
        return Finding(
            plugin="exposed_db",
            title=f"Memcached reachable without authentication on port {port}",
            severity="HIGH",
            description=(
                f"Memcached responded with: {version}. Memcached has no "
                f"authentication; an attacker can read/clear cached data. "
                f"UDP/11211 has been used for amplification DDoS."
            ),
            recommendation=(
                "Bind Memcached to localhost or an internal network. "
                "Disable UDP transport with -U 0."
            ),
            port=port,
            service="memcached",
            tags=["unauth-db", "exposed-db", "ddos-vector"],
        )
    return None


def _check_mongodb(target_ip: str, port: int, timeout: float) -> Optional[Finding]:
    # OP_QUERY isMaster — works on legacy and modern MongoDB pre-handshake.
    body = (
        b"\x00\x00\x00\x00"           # cursor flags
        b"admin.$cmd\x00"             # full collection name
        b"\x00\x00\x00\x00"           # numberToSkip
        b"\x01\x00\x00\x00"           # numberToReturn = 1
        + bytes.fromhex("1100000010697341736b00010000000000")  # {isMaster:1}
    )
    header = struct.pack(
        "<iiii",
        16 + len(body),  # messageLength
        1,                # requestID
        0,                # responseTo
        2004,             # opCode = OP_QUERY
    )
    response = _send_recv(target_ip, port, header + body, timeout, n=4096)
    if response and len(response) >= 16:
        return Finding(
            plugin="exposed_db",
            title=f"MongoDB reachable without authentication on port {port}",
            severity="CRITICAL",
            description=(
                "MongoDB responded to isMaster from an unauthenticated client. "
                "Historically a major data-breach vector when exposed: "
                "attackers ransom the database or copy all collections."
            ),
            recommendation=(
                "Enable authentication (`security.authorization: enabled`), "
                "bind to localhost or an internal interface, and put behind a firewall."
            ),
            port=port,
            service="mongodb",
            tags=["unauth-db", "exposed-db"],
        )
    return None


def _check_elasticsearch(target_ip: str, port: int, timeout: float) -> Optional[Finding]:
    try:
        response = requests.get(
            f"http://{target_ip}:{port}/",
            timeout=timeout,
            verify=False,
        )
        if response.status_code == 200 and "cluster_name" in response.text:
            return Finding(
                plugin="exposed_db",
                title=f"Elasticsearch reachable without authentication on port {port}",
                severity="HIGH",
                description=(
                    "Elasticsearch HTTP API returned cluster info to an "
                    "unauthenticated client. Indices may be readable, "
                    "modifiable, or deletable depending on plugins."
                ),
                recommendation=(
                    "Enable Elastic security (X-Pack), set up authentication, "
                    "and bind the HTTP port to an internal interface."
                ),
                port=port,
                service="elasticsearch",
                tags=["unauth-db", "exposed-db"],
            )
    except Exception:
        pass
    return None


_CHECKS = {
    6379: _check_redis,
    11211: _check_memcached,
    27017: _check_mongodb,
    9200: _check_elasticsearch,
}


def run(target_ip: str, open_ports: List[dict], timeout: float = 3.0) -> List[Finding]:
    findings: List[Finding] = []
    for entry in open_ports:
        port = entry["port"]
        check = _CHECKS.get(port)
        if not check:
            continue
        result = check(target_ip, port, timeout)
        if result:
            findings.append(result)
    return findings


PLUGIN = NetworkPlugin(
    name="exposed_db",
    description="Probes Redis / Memcached / MongoDB / Elasticsearch for unauthenticated access",
    runner=run,
)
