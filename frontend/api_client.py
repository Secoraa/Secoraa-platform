"""
FastAPI Client - All backend API calls
"""
import requests
import os
from typing import Optional, Dict, List

# Backend URL - can be overridden with environment variable
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")


# ==========================================
# Asset Discovery APIs
# ==========================================

def get_domains() -> List[Dict]:
    """Get all domains with subdomains"""
    try:
        resp = requests.get(f"{BACKEND_URL}/assets/domain", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        raise Exception(f"Failed to fetch domains: {str(e)}")


def get_domain_by_id(domain_id: str) -> Dict:
    """Get domain by ID"""
    try:
        resp = requests.get(f"{BACKEND_URL}/assets/domain/{domain_id}", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        raise Exception(f"Failed to fetch domain: {str(e)}")


def create_domain(domain_name: str, tags: Optional[List[str]] = None) -> Dict:
    """Create a new domain"""
    try:
        payload = {
            "domain_name": domain_name,
            "tags": tags or []
        }
        resp = requests.post(f"{BACKEND_URL}/assets/domain", json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        raise Exception(f"Failed to create domain: {str(e)}")


def update_domain(domain_id: str, tags: List[str]) -> Dict:
    """Update domain tags"""
    try:
        payload = {"tags": tags}
        resp = requests.patch(f"{BACKEND_URL}/assets/domain/{domain_id}", json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        raise Exception(f"Failed to update domain: {str(e)}")


# ==========================================
# Scan APIs
# ==========================================

def create_scan(scan_name: str, scan_type: str, domain: str) -> Dict:
    """Create and run a new scan"""
    try:
        payload = {
            "scan_name": scan_name,
            "scan_type": scan_type,
            "payload": {
                "domain": domain
            }
        }
        resp = requests.post(f"{BACKEND_URL}/scans/", json=payload, timeout=300)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        raise Exception(f"Failed to run scan: {str(e)}")


def get_all_scans() -> Dict:
    """Get all scans"""
    try:
        resp = requests.get(f"{BACKEND_URL}/scans/scan", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        raise Exception(f"Failed to fetch scans: {str(e)}")


def get_scan_by_id(scan_id: str) -> Dict:
    """Get scan by ID"""
    try:
        resp = requests.get(f"{BACKEND_URL}/scans/scan/{scan_id}", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        raise Exception(f"Failed to fetch scan: {str(e)}")


def get_scan_results(scan_id: str) -> Dict:
    """Get scan results (subdomains)"""
    try:
        resp = requests.get(f"{BACKEND_URL}/scans/{scan_id}/results", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        raise Exception(f"Failed to fetch scan results: {str(e)}")
