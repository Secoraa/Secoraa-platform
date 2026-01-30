from app.scanners.dd_scanner import DomainDiscoveryScanner
from app.scanners.subdomain_scanner.scanner import SubdomainScanner
from app.scanners.network_scanner.network_scanner import NetworkScanner

SCANNERS = {
    "dd": DomainDiscoveryScanner(),
    "subdomain": SubdomainScanner(),
    "network": NetworkScanner(),
}
