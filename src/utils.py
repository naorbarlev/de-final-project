from datetime import datetime
from minio.error import S3Error
import io
import dotenv
from elasticsearch import Elasticsearch
from kafka import KafkaConsumer
import os
import time
from logger import get_logger

logger = get_logger(__name__)

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
    response = None
    try:
        # Fetch the object from MinIO
        response = client.get_object(bucket_name, object_name)
        logger.info(f"response.status: {response.status}")
        if response.status == 200:
            # Read the content as raw bytes
            file_bytes = response.read()
            file_text = file_bytes.decode('utf-8')
        else:
            logger.info(f"Failed to read watermark file '{object_name}' from bucket '{bucket_name}'. HTTP status: {response.status}")
            return None
            
    except S3Error as e:
        if e.code == "NoSuchKey":
            logger.info(f"Watermark file '{object_name}' not found in bucket '{bucket_name}'. Returning None.")
            return None
        else:
            raise e
    finally:
        if response is not None:
            response.close()
            response.release_conn()

    logger.info(f"Watermark file '{object_name}' content: {file_text}")
    if file_text:
        return datetime.strptime(file_text, date_format)
    else:
        logger.info(f"Watermark file '{object_name}' is empty. Returning None.")
        return None


def write_watermark_date(client, bucket_name, object_name, date: datetime, date_format="%Y-%m-%dT%H:%M:%S"):
    new_watermark = date.strftime(date_format)
    client.put_object(
            bucket_name=bucket_name,
            object_name=object_name,
            data=io.BytesIO(new_watermark.encode('utf-8')),
            length=len(new_watermark),
            content_type="application/text"
        )
    
    

def wait_for_elasticsearch(es_client, retries=30, delay=5):
    """Wait until Elasticsearch responds to ping or raise after retries."""

    for attempt in range(1, retries + 1):
        try:
            if es_client.ping():
                logger.info(f"Elasticsearch reachable (attempt {attempt})")
                return True
        except Exception as e:
            logger.error(f"Elasticsearch ping failed (attempt {attempt}): {e}")
        time.sleep(delay)
    raise RuntimeError("Elasticsearch not reachable after retries")


def consume_from_kafka_and_send_to_es(consumer: KafkaConsumer, es: Elasticsearch, es_index:str):
    logger.info("Consuming data from Kafka...")
    for message in consumer:
        logger.info(f"Offset: {message.offset}")   
        log = message.value
        es.index(index=es_index, body=log)  # Index data into Elasticsearch
        
        
def es_index_get_or_create(es:Elasticsearch, index_name, mapping):
    if not es.indices.exists(index=index_name):
        # Create the index with mapping
        es.indices.create(index=index_name, body=mapping)
        logger.info(f"Created Elasticsearch index: {index_name} with custom mapping")