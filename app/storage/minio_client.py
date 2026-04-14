import json
import logging
import os
import warnings
from io import BytesIO
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

from minio import Minio
from minio.error import S3Error

logger = logging.getLogger(__name__)

# Suppress urllib3 OpenSSL warning (harmless on macOS with LibreSSL)
warnings.filterwarnings("ignore", message=".*urllib3.*OpenSSL.*", category=UserWarning)

# Try to load .env file if it exists (local dev only)
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass

BUCKET = os.getenv("R2_BUCKET") or os.getenv("MINIO_BUCKET", "secoraa-scan-outputs")

# Keep old name as alias so existing imports still work
MINIO_BUCKET = BUCKET

# Lazy global client
client = None
_using_r2 = False
_init_attempted = False


def _build_client() -> Optional[Minio]:
    """
    Build an S3-compatible client.
    Priority: Cloudflare R2 env vars → local MinIO env vars.
    """
    global _using_r2

    # --- Try Cloudflare R2 first ---
    r2_endpoint = os.getenv("R2_ENDPOINT")
    r2_access = os.getenv("R2_ACCESS_KEY")
    r2_secret = os.getenv("R2_SECRET_KEY")

    if all([r2_endpoint, r2_access, r2_secret]):
        # R2 endpoint is a full URL like https://xxx.r2.cloudflarestorage.com
        # Minio client needs just the host (without scheme)
        parsed = urlparse(r2_endpoint)
        host = parsed.netloc or parsed.path  # handle with/without scheme
        _using_r2 = True
        logger.info("Using Cloudflare R2 storage: %s", host)
        return Minio(
            endpoint=host,
            access_key=r2_access,
            secret_key=r2_secret,
            secure=True,
            region="auto",
        )

    # --- Fall back to local MinIO ---
    minio_endpoint = os.getenv("MINIO_ENDPOINT")
    minio_access_key = os.getenv("MINIO_ACCESS_KEY") or os.getenv("MINIO_ROOT_USER")
    minio_secret_key = os.getenv("MINIO_SECRET_KEY") or os.getenv("MINIO_ROOT_PASSWORD")

    if not all([minio_endpoint, minio_access_key, minio_secret_key]):
        logger.warning(
            "Object storage not configured — file storage features disabled. "
            "Set R2_ENDPOINT/R2_ACCESS_KEY/R2_SECRET_KEY (Cloudflare R2) or "
            "MINIO_ENDPOINT/MINIO_ACCESS_KEY/MINIO_SECRET_KEY (MinIO) to enable."
        )
        return None

    raw_secure = os.getenv("MINIO_SECURE")
    if raw_secure is not None:
        minio_secure = raw_secure.lower() == "true"
    else:
        ep = minio_endpoint.lower()
        minio_secure = not (
            "localhost" in ep
            or ep.startswith("127.0.0.1")
            or ep.startswith("0.0.0.0")
        )

    _using_r2 = False
    logger.info("Using local MinIO storage: %s", minio_endpoint)
    return Minio(
        endpoint=minio_endpoint,
        access_key=minio_access_key,
        secret_key=minio_secret_key,
        secure=minio_secure,
    )


def get_minio_client() -> Optional[Minio]:
    """
    Get S3-compatible client with lazy initialization.
    Works with Cloudflare R2 and local MinIO.
    """
    global client, _init_attempted
    if client is not None:
        return client
    if _init_attempted:
        return None
    _init_attempted = True
    client = _build_client()
    return client


def is_minio_configured() -> bool:
    """Check if any object storage is configured."""
    return bool(os.getenv("R2_ENDPOINT") or os.getenv("MINIO_ENDPOINT"))


def ensure_bucket():
    global client
    if client is None:
        client = get_minio_client()
    if client is None:
        return

    try:
        if not client.bucket_exists(BUCKET):
            # R2 buckets are created via dashboard; only auto-create for local MinIO
            if not _using_r2:
                client.make_bucket(BUCKET)
    except S3Error as e:
        # R2 may return 403 for bucket_exists if token is scoped to object ops only
        if _using_r2 and e.code in ("AccessDenied", "AllAccessDisabled"):
            logger.debug("R2 bucket_exists check denied (expected with scoped tokens) — assuming bucket exists")
        else:
            raise


def upload_file_to_minio(file_path: str, object_name: str = None):
    """Upload a file from local filesystem to object storage."""
    global client
    if client is None:
        client = get_minio_client()
    if client is None:
        logger.warning("Object storage not configured — skipping file upload")
        return

    ensure_bucket()

    file_path_obj = Path(file_path)
    if not file_path_obj.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if object_name is None:
        object_name = file_path_obj.name

    try:
        with open(file_path_obj, "rb") as file_data:
            file_stat = file_path_obj.stat()
            client.put_object(
                bucket_name=BUCKET,
                object_name=object_name,
                data=file_data,
                length=file_stat.st_size,
                content_type="application/octet-stream",
            )
    except Exception as e:
        raise Exception(f"Failed to upload {file_path}: {str(e)}")


def upload_bytes_to_minio(
    data: bytes,
    object_name: str,
    content_type: str = "application/octet-stream",
) -> Tuple[str, str]:
    """Upload raw bytes to object storage (PDFs, reports, etc.)"""
    global client
    if client is None:
        client = get_minio_client()
    if client is None:
        logger.warning("Object storage not configured — skipping bytes upload")
        return ("", "")

    ensure_bucket()

    try:
        bio = BytesIO(data)
        client.put_object(
            bucket_name=BUCKET,
            object_name=object_name,
            data=bio,
            length=len(data),
            content_type=content_type,
        )
        return BUCKET, object_name
    except Exception as e:
        raise Exception(f"Failed to upload bytes: {str(e)}")


def get_object_stream(object_name: str):
    """
    Get a streaming response for an object.
    Caller must close the response.
    """
    global client
    if client is None:
        client = get_minio_client()
    if client is None:
        raise RuntimeError("Object storage not configured — cannot retrieve objects")

    return client.get_object(BUCKET, object_name)


def get_object_content_type(object_name: str) -> Optional[str]:
    global client
    if client is None:
        client = get_minio_client()
    if client is None:
        return None

    try:
        stat = client.stat_object(BUCKET, object_name)
        return getattr(stat, "content_type", None)
    except S3Error:
        return None


def download_json(object_name: str):
    global client
    if client is None:
        client = get_minio_client()
    if client is None:
        raise RuntimeError("Object storage not configured — cannot download objects")

    response = client.get_object(BUCKET, object_name)
    try:
        return json.load(response)
    finally:
        response.close()
        response.release_conn()


def object_exists(object_name: str) -> bool:
    global client
    if client is None:
        client = get_minio_client()
    if client is None:
        return False

    try:
        client.stat_object(BUCKET, object_name)
        return True
    except S3Error:
        return False
