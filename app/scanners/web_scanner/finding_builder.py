from typing import List, Dict, Any

from app.scanners.web_scanner.utils.helpers import generate_uuid, random_asset_ref, hash_for_poc
from app.scanners.web_scanner.vuln_db import VULN_DB


def build_finding(vuln_key: str, exec_id: str, tenant: str, urls: List[str]) -> Dict[str, Any]:
    if vuln_key not in VULN_DB:
        raise ValueError(f"Unknown vulnerability key: {vuln_key}")

    vuln_def = VULN_DB[vuln_key]
    vuln_uuid = generate_uuid()
    poc_hash = hash_for_poc(vuln_uuid)
    poc_path = f"poc/{tenant}/workflow/{exec_id}/{poc_hash}.png"

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
        "vulnerability": {
            **vuln_def["vulnerability"],
            "uuid": vuln_uuid,
        },
    }
