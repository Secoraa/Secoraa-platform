from __future__ import annotations

import logging
import random
import socket

from app.scanners.base import BaseScanner
from app.scanners.subdomain_scanner.discovery.bruteforce import bruteforce_subdomains
from app.scanners.subdomain_scanner.discovery.passive import fetch_all_passive
from app.scanners.subdomain_scanner.validation.dns_check import validate_dns

logger = logging.getLogger(__name__)


class DomainDiscoveryScanner(BaseScanner):
    name = "dd"

    def _resolve_ip(self, hostname: str) -> str | None:
        """Resolve hostname to IP address. Returns None if resolution fails."""
        try:
            return socket.gethostbyname(hostname)
        except (socket.gaierror, socket.herror, OSError):
            return None

    def _filter_wildcards(self, subdomains: list, domain: str) -> list:
        """Filter out wildcard subdomains from the list."""
        # Detect wildcard DNS by resolving random non-existent subdomains
        wildcard_test_subdomains = [
            f"xzq-nonexist-{random.randint(100000, 999999)}.{domain}",
            f"xzq-nohost-{random.randint(100000, 999999)}.{domain}",
            f"xzq-fakesub-{random.randint(100000, 999999)}.{domain}",
        ]

        wildcard_ips: set[str] = set()
        for test_sub in wildcard_test_subdomains:
            test_ip = self._resolve_ip(test_sub)
            if test_ip:
                wildcard_ips.add(test_ip)

        if wildcard_ips:
            logger.info(
                "Wildcard DNS detected for %s, IPs: %s — will filter matches",
                domain, wildcard_ips,
            )

        # Filter subdomains
        valid_subdomains = []
        filtered_count = 0

        for subdomain in subdomains:
            subdomain = subdomain.strip()
            if not subdomain:
                continue

            # Only filter literal wildcards
            if "*" in subdomain:
                filtered_count += 1
                continue

            # If wildcard DNS detected, filter subdomains that resolve to wildcard IP
            if wildcard_ips:
                subdomain_ip = self._resolve_ip(subdomain)
                if subdomain_ip in wildcard_ips:
                    filtered_count += 1
                    continue

            valid_subdomains.append(subdomain)

        logger.info(
            "Wildcard filtering for %s: %d input → %d valid (%d filtered)",
            domain, len(subdomains), len(valid_subdomains), filtered_count,
        )
        return valid_subdomains

    def run(self, payload: dict) -> dict:
        domain = payload["domain"]
        logger.info("Starting DD scan for %s", domain)

        # 1. Passive discovery (crt.sh + HackerTarget + AlienVault + RapidDNS)
        passive = fetch_all_passive(domain)
        logger.info("Passive discovery found %d subdomains for %s", len(passive), domain)

        # 2. Bruteforce discovery (~500 common words)
        brute = set(bruteforce_subdomains(domain))
        logger.info("Bruteforce generated %d candidates for %s", len(brute), domain)

        # 3. Merge and deduplicate
        discovered = list(passive.union(brute))
        logger.info("Total unique candidates: %d for %s", len(discovered), domain)

        # 4. DNS validation (A, AAAA, CNAME)
        resolved = validate_dns(discovered)
        all_subdomains = list(set(resolved))
        logger.info("DNS-resolved subdomains: %d for %s", len(all_subdomains), domain)

        # 5. Filter wildcards
        valid_subdomains = self._filter_wildcards(all_subdomains, domain)

        logger.info(
            "DD scan complete for %s: %d valid subdomains (from %d discovered)",
            domain, len(valid_subdomains), len(discovered),
        )

        return {
            "scan_type": self.name,
            "domain": domain,
            "subdomains": valid_subdomains,
            "total_found": len(valid_subdomains),
            "total_before_filtering": len(all_subdomains),
        }
