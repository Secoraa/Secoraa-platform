import json
import os
import warnings
from io import BytesIO
from pathlib import Path
from typing import Optional, Tuple
from minio import Minio
from minio.error import S3Error
from urllib3 import response

# Suppress urllib3 OpenSSL warning (harmless on macOS with LibreSSL)
warnings.filterwarnings("ignore", message=".*urllib3.*OpenSSL.*", category=UserWarning)

# Try to load .env file if it exists
try:
    from dotenv import load_dotenv
    # Load .env from project root (parent of app directory)
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  # python-dotenv not installed, skip

MINIO_BUCKET = "secoraa-scan-outputs"

def get_minio_client():
    """
    Get MinIO client with lazy initialization.
    This ensures environment variables are loaded before creating the client.
    """
    global client
    
    # If client is already initialized, return it
    if client is not None:
        return client
    
    # Get credentials with better error handling
    minio_endpoint = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    minio_user = os.getenv("MINIO_ROOT_USER")
    minio_password = os.getenv("MINIO_ROOT_PASSWORD")

    if not minio_user or not minio_password:
        raise ValueError(
            "MinIO credentials not found. Please set MINIO_ROOT_USER and MINIO_ROOT_PASSWORD "
            "environment variables or add them to a .env file in the project root."
        )

    # Create and store the client
    client = Minio(
        endpoint=minio_endpoint,
        access_key=minio_user,
        secret_key=minio_password,
        secure=False,
    )
    
    return client

# Initialize client lazily
client = None

def ensure_bucket():
    global client
    if client is None:
        client = get_minio_client()
    if not client.bucket_exists(MINIO_BUCKET):
        client.make_bucket(MINIO_BUCKET)

def upload_file_to_minio(file_path: str, object_name: str = None):
    """
    Upload a file from local filesystem to MinIO.
    
    Args:
        file_path: Path to the local file to upload
        object_name: Optional name to use for the object in MinIO (defaults to filename)
    """
    global client
    if client is None:
        client = get_minio_client()
    
    ensure_bucket()  # ✅ ALWAYS ensure bucket
    
    file_path_obj = Path(file_path)
    if not file_path_obj.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if object_name is None:
        object_name = file_path_obj.name

    try:
        print(f"🔼 Uploading {file_path} to MinIO as {object_name}")
        with open(file_path_obj, "rb") as file_data:
            file_stat = file_path_obj.stat()
            print(f"   - File size: {file_stat.st_size} bytes")
            print(f"   - Bucket: {MINIO_BUCKET}")
            
            client.put_object(
                bucket_name=MINIO_BUCKET,
                object_name=object_name,
                data=file_data,
                length=file_stat.st_size,
                content_type="application/json",
            )
        print(f"✅ Successfully uploaded {object_name} to MinIO")
    except Exception as e:
        print(f"❌ Failed to upload {file_path} to MinIO as {object_name}: {str(e)}")
        raise Exception(f"Failed to upload {file_path} to MinIO as {object_name}: {str(e)}")


def upload_bytes_to_minio(data: bytes, object_name: str, content_type: str = "application/octet-stream") -> Tuple[str, str]:
    """
    Upload raw bytes to MinIO (useful for PDFs, etc.)

    Returns:
        (bucket_name, object_name)
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
        return (MINIO_BUCKET, object_name)
    except Exception as e:
        raise Exception(f"Failed to upload bytes to MinIO as {object_name}: {str(e)}")


def get_object_stream(object_name: str):
    """
    Get a streaming response for an object stored in MinIO.
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

def download_json(object_name:str):
    global client
    if client is None:
        client = get_minio_client()
    response = client.get_object(MINIO_BUCKET,object_name)
    return json.load(response)

def object_exists(object_name: str) -> bool:
    global client
    if client is None:
        client = get_minio_client()
    try:
        client.stat_object(MINIO_BUCKET, object_name)
        return True
    except S3Error:
        return False