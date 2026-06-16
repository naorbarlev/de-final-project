from datetime import datetime
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
    try:
        # Fetch the object from MinIO
        response = client.get_object(bucket_name, object_name)
        
        # Read the content as raw bytes
        file_bytes = response.read()
        file_text = file_bytes.decode('utf-8')

    finally:
        response.close()
        response.release_conn()
    
    if file_text:
        return datetime.strptime(file_text, date_format)
    else:
        return None   