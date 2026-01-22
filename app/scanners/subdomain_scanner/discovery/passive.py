# app/scanners/subdomain_scanner/discovery/passive.py

import requests
from typing import Set


def fetch_from_crtsh(domain: str) -> Set[str]:
    """
    Fetch subdomains from crt.sh (certificate transparency logs)
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            return subdomains

        data = response.json()
        for entry in data:
            name = entry.get("name_value")
            if name:
                for sub in name.split("\n"):
                    if sub.endswith(domain):
                        subdomains.add(sub.strip())

    except Exception:
        pass

    return subdomains
