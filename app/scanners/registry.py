from app.scanners.dd_scanner import DomainDiscoveryScanner
from app.scanners.subdomain_scanner.scanner import SubdomainScanner

SCANNERS = {
    "dd": DomainDiscoveryScanner(),
    "subdomain": SubdomainScanner(),
}
