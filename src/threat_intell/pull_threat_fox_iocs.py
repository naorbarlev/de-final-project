from urllib import response

from pathlib import Path
import sys
import requests
import json
import dotenv
import os
from minio import Minio
from datetime import datetime, timedelta
import io

dotenv.load_dotenv()
SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
    
from utils import get_ioc_file_name, read_watermark_date, write_watermark_date



API_URL = "https://threatfox-api.abuse.ch/api/v1/"
BUCKET_NAME = os.getenv("IOCS_BUCKET_NAME")
RAW_IOCS_FOLDER_NAME = os.getenv("RAW_IOCS_FOLDER_NAME")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT")
WATERMARK_OBJECT_NAME = "watermark.txt"
date_format = "%Y-%m-%dT%H:%M:%S"


def pull_iocs(api_url, api_key, days=1):
    
    if not api_key:
        raise ValueError("API key is required to pull IOCs from ThreatFox.")
    
    if not days or (days < 1 or days > 7):
        raise ValueError("Days parameter is required and must be a positive integer between 1 and 7.")

    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    payload = {
        "query": "get_iocs",
        "days": int(days)  # Convert to negative for the API
    }
    response = requests.post(api_url, headers=headers, json=payload)
    response.raise_for_status()  # Raise an exception for HTTP errors
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to pull IOCs: {response.status_code} - {response.text}")


def get_days_ago(timestamp):
    
    '''Calculate days passed since the given timestamp'''
    if not timestamp and type(timestamp) != datetime:
        return None
    now = datetime.now()
    delta = now - timestamp
    return delta.days
     
    
def upload_iocs_to_minio(client, data, bucket_name):
    
    if not data:
        print("No data to upload.")
        return
    
    if not MINIO_ACCESS_KEY or not MINIO_SECRET_KEY:
        raise ValueError("MinIO access key and secret key are required to upload data to MinIO.")
    
    json_str = json.dumps(data)
    json_bytes = json_str.encode("utf-8")  # convert string → bytes
    data_stream = io.BytesIO(json_bytes)
    
    object_name = get_ioc_file_name(datetime.now())
    
    print(len(json_bytes))
      
    # Create bucket if not exists
    if not client.bucket_exists(bucket_name):
        client.make_bucket(bucket_name)
    
    try:
        client.put_object(
            bucket_name=bucket_name,
            object_name=object_name,
            data=data_stream,
            length=len(json_bytes),  # Length of the data in bytes
            content_type="application/json"
        )
        print(f"Uploaded {object_name} to MinIO bucket '{bucket_name}'")
    except Exception as e:
        print(f"Error uploading to MinIO: {e}")
        raise e
    
    try:
        write_watermark_date(client, BUCKET_NAME, f"{RAW_IOCS_FOLDER_NAME}/{WATERMARK_OBJECT_NAME}", datetime.now())
        print(f"Watermark updated to: {datetime.now()}")
    except Exception as e:
        raise e
    

if __name__ == "__main__":
    
    # Connect to MinIO
    try:
        client = Minio(
            endpoint=MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=False
        )
    except Exception as e:
        print(f"Error connecting to MinIO: {e}")
        sys.exit(1)
    
    watermark_date = read_watermark_date(client, bucket_name=BUCKET_NAME, object_name=f"{RAW_IOCS_FOLDER_NAME}/{WATERMARK_OBJECT_NAME}")
    days_since_watermark = get_days_ago(watermark_date)
    if days_since_watermark == 0:
        print("All IOCs are up to date. No new data to pull.")
        sys.exit(0)
    
    if days_since_watermark is None:
        print("No watermark found. Pulling IOCs for the last 7 days.")
        days_since_watermark = 7
    iocs = pull_iocs(API_URL, THREATFOX_API_KEY, days=days_since_watermark)
    if iocs:
        upload_iocs_to_minio(client, iocs, bucket_name=BUCKET_NAME)