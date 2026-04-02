import json
import re
from pathlib import Path

from app.storage.minio_client import upload_file_to_minio

BASE_DIR = Path("scan_results")
BASE_DIR.mkdir(exist_ok=True)


def _safe_name(name: str) -> str:
    """Replace spaces and special chars with underscores for MinIO-safe filenames."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name)


def save_scan_result(scan_name: str, scan_id: str, scan_type: str, data: dict) -> str:
    file_path = BASE_DIR / f"{scan_type}_{_safe_name(scan_name)}_{scan_id}.json"

    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

    return str(file_path)
