from app.scanners.dd_scanner import DomainDiscoveryScanner
from app.scanners.subdomain_scanner.scanner import SubdomainScanner
from app.scanners.network_scanner.network_scanner import NetworkScanner
from app.scanners.vulnerability_scanner import VulnerabilityScanner

SCANNERS = {
    "dd": DomainDiscoveryScanner(),
    "subdomain": SubdomainScanner(),
    "network": NetworkScanner(),
    "vulnerability": VulnerabilityScanner(),
}
