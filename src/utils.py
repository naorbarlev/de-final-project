from datetime import datetime
from minio.error import S3Error
import io
import dotenv
import os

dotenv.load_dotenv()

RAW_IOCS_FOLDER_NAME = os.getenv("RAW_IOCS_FOLDER_NAME")

def get_ioc_file_name(day: datetime):
    '''Generate a file name for IOCs based on the given datetime using Hive-style partitions.'''
    folder_path = f"{RAW_IOCS_FOLDER_NAME}/year={day.year}/month={day.month:02d}/day={day.day:02d}/"
    filename = f"iocs_{day.hour:02d}{day.minute:02d}.json"
    object_name = f"{folder_path}{filename}"
    return object_name


def read_watermark_date(client, bucket_name, object_name, date_format="%Y-%m-%dT%H:%M:%S"):
    file_bytes = None
    file_text = None
    try:
        # Fetch the object from MinIO
        response = client.get_object(bucket_name, object_name)
        if response.status != 200:
            
            response = client.get_object(bucket_name, object_name)
            
        # Read the content as raw bytes
        file_bytes = response.read()
        file_text = file_bytes.decode('utf-8')
    except S3Error as e:
        if e.code == "NoSuchKey":
            write_watermark_date(client, bucket_name, object_name, datetime.now())
            response = client.get_object(bucket_name, object_name)
            file_bytes = response.read()
            file_text = file_bytes.decode('utf-8')
        else:
            raise e
    finally:
        response.close()
        response.release_conn()
    
    if file_text:
        return datetime.strptime(file_text, date_format)
    else:
        raise ValueError(f"Watermark file {object_name} is empty or not found in bucket {bucket_name}.")


def write_watermark_date(client, bucket_name, object_name, date: datetime, date_format="%Y-%m-%dT%H:%M:%S"):
    new_watermark = date.strftime(date_format)
    client.put_object(
            bucket_name=bucket_name,
            object_name=object_name,
            data=io.BytesIO(new_watermark.encode('utf-8')),
            length=len(new_watermark),
            content_type="application/text"
        )
    