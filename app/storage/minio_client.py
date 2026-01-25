import json
import os
import warnings
from io import BytesIO
from pathlib import Path
from typing import Optional, Tuple

from minio import Minio
from minio.error import S3Error

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

MINIO_BUCKET = "secoraa-scan-outputs"

# Lazy global client
client = None


def get_minio_client() -> Minio:
    """
    Get MinIO client with lazy initialization.
    Safe for Railway & local dev.
    """
    global client

    if client is not None:
        return client

    minio_endpoint = os.getenv("MINIO_ENDPOINT")
    minio_access_key = os.getenv("MINIO_ACCESS_KEY")
    minio_secret_key = os.getenv("MINIO_SECRET_KEY")
    minio_secure = os.getenv("MINIO_SECURE", "true").lower() == "true"

    if not all([minio_endpoint, minio_access_key, minio_secret_key]):
        raise RuntimeError(
            "MinIO is not configured. "
            "Please set MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY."
        )

    client = Minio(
        endpoint=minio_endpoint,
        access_key=minio_access_key,
        secret_key=minio_secret_key,
        secure=minio_secure,
    )

    return client


def ensure_bucket():
    global client
    if client is None:
        client = get_minio_client()

    if not client.bucket_exists(MINIO_BUCKET):
        client.make_bucket(MINIO_BUCKET)


def upload_file_to_minio(file_path: str, object_name: str = None):
    """
    Upload a file from local filesystem to MinIO.
    """
    global client
    if client is None:
        client = get_minio_client()

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
                bucket_name=MINIO_BUCKET,
                object_name=object_name,
                data=file_data,
                length=file_stat.st_size,
                content_type="application/octet-stream",
            )
    except Exception as e:
        raise Exception(f"Failed to upload {file_path} to MinIO: {str(e)}")


def upload_bytes_to_minio(
    data: bytes,
    object_name: str,
    content_type: str = "application/octet-stream",
) -> Tuple[str, str]:
    """
    Upload raw bytes to MinIO (PDFs, reports, etc.)
    """
    global client
    if client is None:
        client = get_minio_client()

    ensure_bucket()

    try:
        bio = BytesIO(data)
        client.put_object(
            bucket_name=MINIO_BUCKET,
            object_name=object_name,
            data=bio,
            length=len(data),
            content_type=content_type,
        )
        return MINIO_BUCKET, object_name
    except Exception as e:
        raise Exception(f"Failed to upload bytes to MinIO: {str(e)}")


def get_object_stream(object_name: str):
    """
    Get a streaming response for an object.
    Caller must close the response.
    """
    global client
    if client is None:
        client = get_minio_client()

    return client.get_object(MINIO_BUCKET, object_name)


def get_object_content_type(object_name: str) -> Optional[str]:
    global client
    if client is None:
        client = get_minio_client()

    try:
        stat = client.stat_object(MINIO_BUCKET, object_name)
        return getattr(stat, "content_type", None)
    except S3Error:
        return None


def download_json(object_name: str):
    global client
    if client is None:
        client = get_minio_client()

    response = client.get_object(MINIO_BUCKET, object_name)
    try:
        return json.load(response)
    finally:
        response.close()
        response.release_conn()


def object_exists(object_name: str) -> bool:
    global client
    if client is None:
        client = get_minio_client()

    try:
        client.stat_object(MINIO_BUCKET, object_name)
        return True
    except S3Error:
        return False
