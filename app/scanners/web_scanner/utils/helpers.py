import hashlib
import uuid
from urllib.parse import urlparse


def normalize_domain(value: str) -> str:
    if not value:
        return ""
    value = value.strip()
    if value.startswith("http://") or value.startswith("https://"):
        return urlparse(value).netloc
    return value


def generate_uuid() -> str:
    return str(uuid.uuid4())


def random_asset_ref() -> str:
    return f"0x{uuid.uuid4().hex[:12]}"


def hash_for_poc(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def is_same_domain(base: str, target: str) -> bool:
    base_host = urlparse(base).netloc
    target_host = urlparse(target).netloc
    return base_host == target_host


def should_skip_url(url: str) -> bool:
    skip_ext = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf", ".zip", ".js", ".css")
    return url.lower().endswith(skip_ext)
