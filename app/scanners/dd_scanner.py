import subprocess
import socket
from app.scanners.base import BaseScanner

class DomainDiscoveryScanner(BaseScanner):
    name = "dd"

    def _resolve_ip(self, hostname: str) -> str:
        """Resolve hostname to IP address. Returns None if resolution fails."""
        try:
            return socket.gethostbyname(hostname)
        except (socket.gaierror, socket.herror, OSError):
            return None

    def _is_wildcard_subdomain(self, subdomain: str, domain: str, wildcard_ip: str = None) -> bool:
        """
        Quick pattern check for obviously invalid/wildcard subdomains.
        Returns True if subdomain should be filtered out.
        """
        # Filter out obviously invalid patterns in subdomain name
        invalid_patterns = [
            '*', 'wildcard', 'invalid', 'nonexistent',
            'random', 'fake', 'dummy', 'placeholder',
            'test123', 'example', 'sample'
        ]
        subdomain_lower = subdomain.lower()
        for pattern in invalid_patterns:
            if pattern in subdomain_lower:
                return True
        
        return False

    def _filter_wildcards(self, subdomains: list, domain: str) -> list:
        """Filter out wildcard subdomains from the list."""
        # First, detect wildcard IP by checking a few random subdomains
        # If multiple random subdomains resolve to the same IP, it's likely a wildcard
        import random
        wildcard_test_subdomains = [
            f"nonexistent-{random.randint(100000, 999999)}.{domain}",
            f"invalid-{random.randint(100000, 999999)}.{domain}",
            f"test-{random.randint(100000, 999999)}.{domain}",
        ]
        
        wildcard_ips = set()
        for test_subdomain in wildcard_test_subdomains:
            test_ip = self._resolve_ip(test_subdomain)
            if test_ip:
                wildcard_ips.add(test_ip)
        
        # If all test subdomains resolve to the same IP, it's definitely a wildcard
        wildcard_ip = list(wildcard_ips)[0] if len(wildcard_ips) == 1 else None
        
        # Filter subdomains
        valid_subdomains = []
        total_checked = 0
        
        for subdomain in subdomains:
            subdomain = subdomain.strip()
            if not subdomain:
                continue
            
            total_checked += 1
            
            # Quick pattern check first (faster)
            if self._is_wildcard_subdomain(subdomain, domain, None):
                continue
            
            # DNS resolution check (slower, but more accurate)
            if wildcard_ip:
                subdomain_ip = self._resolve_ip(subdomain)
                if subdomain_ip == wildcard_ip:
                    continue
                # If it doesn't resolve, it might still be valid (just not live)
                # So we keep it if it doesn't match wildcard IP
            
            valid_subdomains.append(subdomain)
        
        return valid_subdomains

    def run(self, payload: dict) -> dict:
        domain = payload["domain"]

        cmd = ["subfinder", "-d", domain, "-silent"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            raise RuntimeError(result.stderr)

        # Get all subdomains from subfinder
        all_subdomains = list(set(result.stdout.splitlines()))
        
        # Filter out wildcards and invalid subdomains
        valid_subdomains = self._filter_wildcards(all_subdomains, domain)

        return {
            "scan_type": self.name,
            "domain": domain,
            "subdomains": valid_subdomains,
            "total_found": len(valid_subdomains),
            "total_before_filtering": len(all_subdomains)
        }
