"""
HTTP / HTTPS service audit — for every open HTTP-ish port, fetch the root
and check security headers, surface admin / debug paths, and flag default
landing pages (Apache It Works, IIS welcome, nginx welcome).
"""
from __future__ import annotations

from typing import List

import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from . import Finding, NetworkPlugin

disable_warnings(InsecureRequestWarning)

_HTTP_PORTS = {80, 81, 591, 2080, 2480, 3000, 4567, 5000, 5104, 5800,
               7001, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9080,
               9090, 16080, 18091, 18092}
_HTTPS_PORTS = {443, 832, 981, 1311, 4444, 4445, 4446, 4711, 4712,
                7000, 7002, 8243, 8333, 8443, 8531, 8888, 9443}

_REQUIRED_HEADERS = {
    "Strict-Transport-Security": (
        "MEDIUM",
        "Without HSTS, browsers can be downgraded to HTTP via a network attacker.",
        "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "X-Content-Type-Options": (
        "LOW",
        "Without nosniff, browsers may MIME-sniff resources and execute disguised payloads.",
        "Add header: X-Content-Type-Options: nosniff",
    ),
    "X-Frame-Options": (
        "MEDIUM",
        "Missing X-Frame-Options enables clickjacking via iframe embedding.",
        "Add header: X-Frame-Options: DENY (or use frame-ancestors in CSP).",
    ),
    "Content-Security-Policy": (
        "MEDIUM",
        "Missing CSP makes XSS exploitation easier and provides no defense in depth.",
        "Define a Content-Security-Policy that restricts script-src, frame-src, etc.",
    ),
}

_DEFAULT_PAGE_MARKERS = [
    (b"It works!", "Apache default page exposed"),
    (b"Welcome to nginx", "nginx default page exposed"),
    (b"IIS Windows Server", "IIS default page exposed"),
    (b"Apache HTTP Server Test Page", "Apache default page exposed"),
    (b"<title>Welcome to CentOS</title>", "CentOS default page exposed"),
]

_ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
    "/manager/html", "/console", "/jenkins", "/.git/config",
    "/server-status", "/server-info", "/actuator", "/metrics",
    "/.env",
]


def _get(url: str, timeout: float):
    try:
        return requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
    except Exception:
        return None


def _audit_url(url: str, port: int, scheme: str, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    response = _get(url, timeout)
    if response is None:
        return findings

    server = response.headers.get("Server")
    if server:
        # Pull a structured (name, version) tuple from common Server-header
        # shapes so the orchestrator's CVE enrichment step can look it up.
        # Examples: "Apache/2.4.7 (Ubuntu)", "nginx/1.14.0", "lighttpd/1.4.45".
        software = None
        for pattern, name in (
            (r"Apache/([0-9][0-9a-z\.\-]*)", "apache"),
            (r"nginx/([0-9][0-9a-z\.\-]*)", "nginx"),
            (r"lighttpd/([0-9][0-9a-z\.\-]*)", "lighttpd"),
            (r"Microsoft-IIS/([0-9][0-9a-z\.\-]*)", "iis"),
        ):
            import re as _re
            m = _re.search(pattern, server, _re.IGNORECASE)
            if m:
                software = {"name": name, "version": m.group(1)}
                break
        findings.append(
            Finding(
                plugin="http_service",
                title=f"Server header discloses software on port {port}",
                severity="LOW",
                description=f"Server header value: {server}",
                recommendation="Remove or anonymize the Server response header.",
                port=port,
                service=scheme,
                tags=["info-disclosure"],
                software=software,
            )
        )

    powered = response.headers.get("X-Powered-By")
    if powered:
        findings.append(
            Finding(
                plugin="http_service",
                title=f"X-Powered-By discloses framework on port {port}",
                severity="LOW",
                description=f"X-Powered-By: {powered}",
                recommendation="Remove the X-Powered-By header.",
                port=port,
                service=scheme,
                tags=["info-disclosure"],
            )
        )

    if scheme == "https":
        for header, (sev, desc, fix) in _REQUIRED_HEADERS.items():
            if header not in response.headers:
                findings.append(
                    Finding(
                        plugin="http_service",
                        title=f"Missing security header: {header}",
                        severity=sev,
                        description=desc,
                        recommendation=fix,
                        port=port,
                        service=scheme,
                        tags=["headers"],
                    )
                )

    body = response.content[:4096]
    for marker, label in _DEFAULT_PAGE_MARKERS:
        if marker in body:
            findings.append(
                Finding(
                    plugin="http_service",
                    title=label,
                    severity="MEDIUM",
                    description=(
                        "A default install page is being served. This usually "
                        "indicates an unconfigured webserver, an abandoned "
                        "host, or one waiting to be properly deployed."
                    ),
                    recommendation=(
                        "Replace the default page with the intended application "
                        "or take the host offline if it's not in use."
                    ),
                    port=port,
                    service=scheme,
                )
            )
            break

    return findings


def _check_admin_paths(base_url: str, port: int, scheme: str, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    for path in _ADMIN_PATHS:
        response = _get(base_url + path, timeout)
        if response is None:
            continue
        if response.status_code in (200, 401, 403):
            severity = "HIGH" if response.status_code == 200 else "MEDIUM"
            findings.append(
                Finding(
                    plugin="http_service",
                    title=f"Admin / sensitive path exposed: {path}",
                    severity=severity,
                    description=(
                        f"Path {path} returned HTTP {response.status_code}. "
                        f"This path commonly indicates an admin console, "
                        f"source code, or configuration leak."
                    ),
                    recommendation=(
                        "Restrict access via firewall, IP allowlist, or "
                        "authentication. Remove the path if not needed."
                    ),
                    port=port,
                    service=scheme,
                    tags=["exposed-admin"],
                )
            )
    return findings


def run(target_ip: str, open_ports: List[dict], timeout: float = 5.0) -> List[Finding]:
    findings: List[Finding] = []
    for entry in open_ports:
        port = entry["port"]
        if port in _HTTP_PORTS:
            base = f"http://{target_ip}:{port}"
        elif port in _HTTPS_PORTS:
            base = f"https://{target_ip}:{port}"
        else:
            continue

        findings.extend(_audit_url(base + "/", port,
                                    "https" if port in _HTTPS_PORTS else "http",
                                    timeout))
        findings.extend(_check_admin_paths(base, port,
                                           "https" if port in _HTTPS_PORTS else "http",
                                           timeout))
    return findings


PLUGIN = NetworkPlugin(
    name="http_service",
    description="Audits HTTP/HTTPS services for headers, info disclosure, default pages, exposed admin paths",
    runner=run,
)
