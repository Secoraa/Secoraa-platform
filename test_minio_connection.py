#!/usr/bin/env python3

"""
Test script to diagnose MinIO connection issues.
"""

import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add the app directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from storage.minio_client import client, MINIO_BUCKET, ensure_bucket

def test_minio_connection():
    """Test MinIO connection and basic operations"""
    
    print("🔍 Testing MinIO connection...")
    
    try:
        # Test 1: Check if client is properly initialized
        print(f"✅ MinIO client initialized with endpoint: {client._endpoint_url}")
        
        # Test 2: Check if bucket exists or create it
        print("📦 Checking bucket existence...")
        ensure_bucket()
        print(f"✅ Bucket '{MINIO_BUCKET}' is ready")
        
        # Test 3: List buckets to verify connection
        print("📋 Listing all buckets...")
        buckets = client.list_buckets()
        for bucket in buckets:
            print(f"   - {bucket.name} (created: {bucket.creation_date})")
        
        # Test 4: Try to upload a small test file
        print("🔼 Testing file upload...")
        test_file_path = "test_upload.json"
        test_data = {"test": "minio_connection_test"}
        
        import json
        with open(test_file_path, "w") as f:
            json.dump(test_data, f)
        
        try:
            from storage.minio_client import upload_file_to_minio
            upload_file_to_minio(test_file_path, "test_connection.json")
            print("✅ Test file uploaded successfully")
            
            # Clean up
            client.remove_object(MINIO_BUCKET, "test_connection.json")
            print("🧹 Test file cleaned up")
            
        except Exception as e:
            print(f"❌ Upload failed: {e}")
            return False
        
        # Clean up test file
        os.remove(test_file_path)
        
        return True
        
    except Exception as e:
        print(f"❌ MinIO connection test failed: {e}")
        return False

def test_minio_endpoint():
    """Test different MinIO endpoints"""
    
    print("\n🌐 Testing different MinIO endpoints...")
    
    endpoints = [
        "localhost:9000",
        "127.0.0.1:9000",
        "secoraa-minio:9000",  # Docker service name
    ]
    
    from minio import Minio
    
    for endpoint in endpoints:
        try:
            print(f"🔗 Testing endpoint: {endpoint}")
            test_client = Minio(
                endpoint=endpoint,
                access_key=os.getenv("MINIO_ROOT_USER"),
                secret_key=os.getenv("MINIO_ROOT_PASSWORD"),
                secure=False,
            )
            
            # Try to list buckets
            buckets = test_client.list_buckets()
            print(f"✅ {endpoint} - Connection successful, found {len(buckets)} buckets")
            
        except Exception as e:
            print(f"❌ {endpoint} - Connection failed: {e}")

if __name__ == "__main__":
    print("🚀 Starting MinIO connection test...")
    
    # Test current connection
    success = test_minio_connection()
    
    # Test different endpoints
    test_minio_endpoint()
    
    if success:
        print("\n🎉 MinIO connection test passed!")
        sys.exit(0)
    else:
        print("\n💥 MinIO connection test failed!")
        sys.exit(1)