"""
DNS misconfiguration probes — for hosts running DNS on UDP/TCP 53, check:
    - Open recursion to arbitrary clients (DNS amplification risk)
    - Zone transfer (AXFR) allowed for common public zones
    - Version disclosure via CHAOS TXT version.bind
"""
from __future__ import annotations

from typing import List

import dns.exception
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.zone

from . import Finding, NetworkPlugin

_DNS_PORTS = {53}


def _check_recursion(target_ip: str, timeout: float) -> bool:
    """Returns True if the target answers recursive queries for a domain it doesn't own."""
    try:
        query = dns.message.make_query("google.com.", dns.rdatatype.A)
        query.flags |= dns.flags.RD
        response = dns.query.udp(query, target_ip, timeout=timeout)
        return any(rrset.rdtype == dns.rdatatype.A for rrset in response.answer)
    except Exception:
        return False


def _version_bind(target_ip: str, timeout: float):
    try:
        query = dns.message.make_query(
            "version.bind.",
            dns.rdatatype.TXT,
            rdclass=dns.rdataclass.CHAOS,
        )
        response = dns.query.udp(query, target_ip, timeout=timeout)
        for rrset in response.answer:
            for item in rrset:
                return str(item).strip('"')
    except Exception:
        return None
    return None


def _try_zone_transfer(target_ip: str, zone: str, timeout: float):
    try:
        return dns.zone.from_xfr(dns.query.xfr(target_ip, zone, timeout=timeout))
    except Exception:
        return None


def run(target_ip: str, open_ports: List[dict], timeout: float = 4.0) -> List[Finding]:
    findings: List[Finding] = []
    if not any(p["port"] in _DNS_PORTS for p in open_ports):
        return findings

    if _check_recursion(target_ip, timeout):
        findings.append(
            Finding(
                plugin="dns_misconfig",
                title="Open DNS resolver — recursion enabled for arbitrary clients",
                severity="HIGH",
                description=(
                    "The DNS server answered a recursive query for a domain "
                    "it is not authoritative for, from an unrelated client "
                    "(this scanner). Open resolvers are abused for DNS "
                    "amplification DDoS attacks."
                ),
                recommendation=(
                    "Disable recursion or restrict it to internal clients "
                    "via 'allow-recursion' (BIND), Access Control Policies "
                    "(Unbound), or equivalent."
                ),
                port=53,
                service="dns",
                tags=["dns-amp", "ddos-vector"],
            )
        )

    version = _version_bind(target_ip, timeout)
    if version:
        findings.append(
            Finding(
                plugin="dns_misconfig",
                title="DNS server discloses software version (version.bind)",
                severity="LOW",
                description=f"version.bind CHAOS TXT response: {version!r}",
                recommendation=(
                    "Override the version.bind response. Example for BIND: "
                    "options { version 'unknown'; };"
                ),
                port=53,
                service="dns",
                tags=["info-disclosure"],
            )
        )

    for zone in {"example.com", "internal.local"}:
        if _try_zone_transfer(target_ip, zone, timeout):
            findings.append(
                Finding(
                    plugin="dns_misconfig",
                    title=f"DNS zone transfer (AXFR) allowed for '{zone}'",
                    severity="HIGH",
                    description=(
                        f"AXFR for '{zone}' completed. An attacker can "
                        f"enumerate every record in the zone, mapping out "
                        f"internal hosts and infrastructure."
                    ),
                    recommendation=(
                        "Restrict AXFR to specific peer name servers via "
                        "allow-transfer (BIND) or transfer-acl (Unbound)."
                    ),
                    port=53,
                    service="dns",
                    tags=["zone-transfer"],
                )
            )

    return findings


PLUGIN = NetworkPlugin(
    name="dns_misconfig",
    description="Probes DNS for open recursion, version disclosure, and zone transfer",
    runner=run,
)
