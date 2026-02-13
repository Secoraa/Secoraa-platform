from typing import List, Dict, Any

from app.scanners.web_scanner.utils.helpers import generate_uuid, random_asset_ref, hash_for_poc
from app.scanners.web_scanner.vuln_db import VULN_DB


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def build_finding(vuln_key: str, exec_id: str, tenant: str, urls: List[str]) -> Dict[str, Any]:
    if vuln_key not in VULN_DB:
        raise ValueError(f"Unknown vulnerability key: {vuln_key}")

    vuln_def = VULN_DB[vuln_key]
    vuln_uuid = generate_uuid()
    poc_hash = hash_for_poc(vuln_uuid)
    poc_path = f"poc/{tenant}/workflow/{exec_id}/{poc_hash}.png"

    vuln_payload = {
        **vuln_def["vulnerability"],
        "uuid": vuln_uuid,
    }
    cvss_score = vuln_payload.get("cvss_score")
    if isinstance(cvss_score, (int, float)):
        vuln_payload["severity"] = _severity_from_cvss(float(cvss_score))

    return {
        "plugin": vuln_def["plugin"],
        "pocs": [
            {
                "asset": random_asset_ref(),
                "order": 1,
                "poc": poc_path,
                "description": "",
                "payloads": None,
                "form": None,
                "urls": urls or [],
            }
        ],
        "vulnerability": vuln_payload,
    }
