"""
Extended port scan — replaces the 10-port socket loop with the nmap top-100
TCP port list. Uses concurrent socket connect_ex() probes via a thread pool.

Output is a list of open ports. This plugin is special: most other plugins
take its open-ports output as input, so it runs first.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from . import Finding, NetworkPlugin

# Curated from nmap's --top-ports 100 (TCP). Covers ~90% of real-world services.
TOP_PORTS: dict = {
    7: "echo", 9: "discard", 13: "daytime", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 26: "rsftp", 37: "time", 53: "dns",
    79: "finger", 80: "http", 81: "http-alt", 88: "kerberos", 106: "poppassd",
    110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 144: "news", 179: "bgp", 199: "smux",
    389: "ldap", 427: "svrloc", 443: "https", 444: "snpp", 445: "smb",
    465: "smtps", 513: "rlogin", 514: "shell", 515: "printer", 543: "klogin",
    544: "kshell", 548: "afp", 554: "rtsp", 587: "submission", 631: "ipp",
    646: "ldp", 873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s",
    1025: "NFS-or-IIS", 1026: "LSA-or-nterm", 1027: "IIS", 1028: "unknown",
    1029: "ms-lsa", 1110: "nfsd-status", 1433: "ms-sql-s", 1720: "h323q931",
    1723: "pptp", 1755: "wms", 1900: "upnp", 2000: "cisco-sccp", 2001: "dc",
    2049: "nfs", 2121: "ccproxy-ftp", 2717: "pn-requester", 3000: "ppp",
    3128: "squid-http", 3306: "mysql", 3389: "ms-wbt-server", 3986: "mapper-ws",
    4899: "radmin", 5000: "upnp", 5009: "airport-admin", 5051: "ida-agent",
    5060: "sip", 5101: "admdog", 5190: "aol", 5357: "wsdapi", 5432: "postgresql",
    5631: "pcanywheredata", 5666: "nrpe", 5800: "vnc-http", 5900: "vnc",
    6000: "X11", 6001: "X11:1", 6646: "unknown", 7070: "realserver",
    8000: "http-alt", 8008: "http", 8009: "ajp13", 8080: "http-proxy",
    8081: "blackice-icecap", 8443: "https-alt", 8888: "sun-answerbook",
    9100: "jetdirect", 9999: "abyss", 10000: "snet-sensor-mgmt", 11211: "memcached",
    27017: "mongodb", 27018: "mongodb-shard", 50000: "ibm-db2", 50070: "hadoop-hdfs",
}


def _probe(target_ip: str, port: int, timeout: float) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        rc = sock.connect_ex((target_ip, port))
        sock.close()
        return rc == 0
    except Exception:
        return False


def run(target_ip: str, open_ports: List[dict], timeout: float = 1.0) -> List[Finding]:
    findings: List[Finding] = []
    discovered: List[dict] = []

    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_probe, target_ip, p, timeout): p for p in TOP_PORTS}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                if fut.result():
                    service = TOP_PORTS[port]
                    discovered.append({"port": port, "service": service})
            except Exception:
                continue

    discovered.sort(key=lambda d: d["port"])
    open_ports.clear()
    open_ports.extend(discovered)

    if not discovered:
        return findings

    open_summary = ", ".join(f"{d['port']}/{d['service']}" for d in discovered)
    findings.append(
        Finding(
            plugin="extended_ports",
            title=f"{len(discovered)} TCP ports open on host",
            severity="INFORMATIONAL",
            description=f"Open ports detected: {open_summary}",
            recommendation=(
                "Audit each open port against your asset inventory. Close any "
                "unused services and put management ports (SSH, RDP, database) "
                "behind a VPN or jump host."
            ),
        )
    )

    risky_ports = {
        21: ("FTP", "MEDIUM", "FTP transmits credentials in cleartext. Migrate to SFTP/FTPS."),
        23: ("Telnet", "HIGH", "Telnet transmits credentials in cleartext. Replace with SSH."),
        135: ("MSRPC", "MEDIUM", "RPC endpoint mapper exposed. Restrict to internal network."),
        139: ("NetBIOS", "MEDIUM", "NetBIOS exposed. Disable on perimeter hosts or restrict via firewall."),
        445: ("SMB", "HIGH", "SMB exposed externally has been the vector for WannaCry/EternalBlue. Block at perimeter."),
        512: ("rexec", "HIGH", "rexec is a deprecated insecure protocol. Disable."),
        513: ("rlogin", "HIGH", "rlogin is a deprecated insecure protocol. Disable."),
        514: ("rsh", "HIGH", "rsh is a deprecated insecure protocol. Disable."),
        1433: ("MS SQL", "HIGH", "Database exposed externally. Restrict to application VPC / VPN."),
        1521: ("Oracle", "HIGH", "Database exposed externally. Restrict to application VPC / VPN."),
        2049: ("NFS", "HIGH", "NFS exposed externally — anonymous reads possible. Restrict access."),
        3306: ("MySQL", "HIGH", "Database exposed externally. Restrict to application VPC / VPN."),
        3389: ("RDP", "HIGH", "RDP exposed to the internet. Use a VPN/Bastion. Brute-force target."),
        5432: ("PostgreSQL", "HIGH", "Database exposed externally. Restrict to application VPC / VPN."),
        5900: ("VNC", "HIGH", "VNC exposed. Often unauthenticated. Move behind a VPN."),
        6379: ("Redis", "HIGH", "Redis often runs without auth. Bind to localhost or set requirepass."),
        9200: ("Elasticsearch", "HIGH", "Elasticsearch HTTP often unauthenticated. Restrict access."),
        11211: ("Memcached", "HIGH", "Memcached UDP has been used for amplification attacks. Disable UDP, restrict TCP."),
        27017: ("MongoDB", "HIGH", "MongoDB has been a major data breach vector when exposed. Bind to localhost."),
    }

    for entry in discovered:
        port = entry["port"]
        if port in risky_ports:
            label, severity, recommendation = risky_ports[port]
            findings.append(
                Finding(
                    plugin="extended_ports",
                    title=f"Risky service exposed: {label} on port {port}",
                    severity=severity,
                    description=(
                        f"Port {port} ({label}) is reachable. This service "
                        f"either uses cleartext credentials, has a history of "
                        f"unauthenticated access, or exposes a database/admin "
                        f"interface that should not be public."
                    ),
                    recommendation=recommendation,
                    port=port,
                    service=label,
                )
            )

    return findings


PLUGIN = NetworkPlugin(
    name="extended_ports",
    description="TCP probe against nmap top-100 ports + risky-service flagging",
    runner=run,
)
