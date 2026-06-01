import requests
import json
import dotenv
import os
from minio import Minio
from datetime import datetime
import io

dotenv.load_dotenv()

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
BUCKET_NAME = "raw-icos"
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")


def pull_iocs(api_url, api_key, days=1):
    
    if not api_key:
        raise ValueError("API key is required to pull IOCs from ThreatFox.")
    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    payload = {
        "query": "get_iocs",
        "days": days
    }
    response = requests.post(api_url, headers=headers, json=payload)
    response.raise_for_status()  # Raise an exception for HTTP errors
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to pull IOCs: {response.status_code} - {response.text}")


def create_file_name():
    today = datetime.now()
    folder_path = f"{today.year}/{today.month:02d}/{today.day:02d}/"
    filename = f"iocs_{today.hour:02d}{today.minute:02d}.json"
    object_name = f"{folder_path}{filename}"
    return object_name


def upload_to_minio(data, bucket_name = "raw-icos"):
    
    if not data:
        print("No data to upload.")
        return
    
    if not MINIO_ACCESS_KEY or not MINIO_SECRET_KEY:
        raise ValueError("MinIO access key and secret key are required to upload data to MinIO.")
    
    json_str = json.dumps(data, ensure_ascii=False)
    json_bytes = json_str.encode("utf-8")  # convert string → bytes
    
    object_name = create_file_name()

    # Connect to MinIO
    client = Minio(
        endpoint=MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False
    )
      
    # Create bucket if not exists
    if not client.bucket_exists(bucket_name):
        client.make_bucket(bucket_name)
    
    try:
        client.put_object(
            bucket_name=bucket_name,
            object_name=object_name,
            data=io.BytesIO(json_bytes),
            length=len(json_bytes),
            content_type="application/json"
        )
    except Exception as e:
        print(f"Error uploading to MinIO: {e}")
        raise e
    
    print(f"Uploaded {object_name} to MinIO bucket '{bucket_name}'")


if __name__ == "__main__":

    iocs = pull_iocs(API_URL, THREATFOX_API_KEY, days=7)
    if iocs:
        upload_to_minio(iocs, bucket_name=BUCKET_NAME)