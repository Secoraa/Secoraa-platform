# app/scanners/subdomain_scanner/vulnerabilities/cve_mapper.py

CVE_DB = {
    "Apache": ["CVE-2021-41773", "CVE-2021-42013"],
    "nginx": ["CVE-2021-23017"],
    "GitHub Pages": ["CVE-2020-11022"],
}


def map_cves(server: str) -> list:
    for key, cves in CVE_DB.items():
        if key.lower() in server.lower():
            return cves
    return []
