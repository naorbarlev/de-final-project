from urllib import response

from elasticsearch import client
import requests
import json
import dotenv
import os
from minio import Minio
from datetime import datetime, timedelta
import io
from utils import get_ioc_file_name, read_watermark_date

dotenv.load_dotenv()

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
BUCKET_NAME = os.getenv("IOCS_BUCKET_NAME")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT")
WATERMARK_OBJECT_NAME = "watermark.txt"
date_format = "%Y-%m-%dT%H:%M:%S"


def pull_iocs(api_url, api_key, days=1):
    
    if not api_key:
        raise ValueError("API key is required to pull IOCs from ThreatFox.")
    
    if not days or days < 1:
        raise ValueError("Days parameter is required and must be a positive integer.")

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


def get_days_ago(timestamp):
    
    '''Calculate days passed since the given timestamp'''
    if not timestamp and type(timestamp) != datetime:
        return None
    now = datetime.now()
    delta = now - timestamp
    return delta.days
     
    

def upload_to_minio(client, data, bucket_name):
    
    if not data:
        print("No data to upload.")
        return
    
    if not MINIO_ACCESS_KEY or not MINIO_SECRET_KEY:
        raise ValueError("MinIO access key and secret key are required to upload data to MinIO.")
    
    json_str = json.dumps(data, ensure_ascii=False)
    json_bytes = json_str.encode("utf-8")  # convert string → bytes
    
    object_name = get_ioc_file_name(datetime.now())
      
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
    
    try:
        new_watermark = datetime.now().strftime(date_format).encode("utf-8")
        client.put_object(
            bucket_name=bucket_name,
            object_name=WATERMARK_OBJECT_NAME,
            data=io.BytesIO(new_watermark),
            length=len(new_watermark),
            content_type="application/text"
        )
    except Exception as e:
        raise e
    
    print(f"Uploaded {object_name} to MinIO bucket '{bucket_name}'")


if __name__ == "__main__":
    
    # Connect to MinIO
    client = Minio(
        endpoint=MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False
    )
    watermark_date = read_watermark_date(client, bucket_name=BUCKET_NAME, object_name=WATERMARK_OBJECT_NAME)
    days_since_watermark = get_days_ago(watermark_date)
    iocs = pull_iocs(API_URL, THREATFOX_API_KEY, days=days_since_watermark)
    if iocs:
        upload_to_minio(client, iocs, bucket_name=BUCKET_NAME)