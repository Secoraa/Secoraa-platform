import sys
import os
import json

# Add parent directory to path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import warnings
# Suppress urllib3 OpenSSL warning
warnings.filterwarnings("ignore", message=".*urllib3.*OpenSSL.*")

from app.storage.minio_client import upload_file_to_minio

# Create a test file first
test_data = {"hello": "minio"}
with open("test.json", "w") as f:
    json.dump(test_data, f)

# Upload the file (object_name is optional, will use filename if not provided)
upload_file_to_minio("test.json")

print("✅ Successfully uploaded test.json to MinIO!")

# Clean up
os.remove("test.json")