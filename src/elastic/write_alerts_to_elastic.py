import sys
from pathlib import Path
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch
import os
import dotenv

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from logger import get_logger


logger = get_logger(__name__)
dotenv.load_dotenv()

KAFKA_BROKER = os.getenv('KAFKA_BROKER')
NETWORK_LOGS_TOPIC = os.getenv('ALERTS_TOPIC')
ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'elasticsearch')

consumer = KafkaConsumer(NETWORK_LOGS_TOPIC, bootstrap_servers=KAFKA_BROKER)

es = Elasticsearch([{'host': ELASTICSEARCH_HOST, 'port': 9200, 'scheme': 'http'}])
es_index = os.getenv('ELASTICSEARCH_ALERTS_INDEX')

def wait_for_elasticsearch(es_client, retries=30, delay=5):
    """Wait until Elasticsearch responds to ping or raise after retries."""
    import time

    for attempt in range(1, retries + 1):
        try:
            if es_client.ping():
                logger.info(f"Elasticsearch reachable (attempt {attempt})")
                return True
        except Exception as e:
            logger.error(f"Elasticsearch ping failed (attempt {attempt}): {e}")
        time.sleep(delay)
    raise RuntimeError("Elasticsearch not reachable after retries")

def consume_from_kafka():
    logger.info("Consuming data from Kafka...")
    for message in consumer:
        log = message.value
        es.index(index=es_index, body=log)  # Index data into Elasticsearch



def es_index_get_or_create(index_name):
    if not es.indices.exists(index=index_name):
        # Define mapping
        # mapping = {}
    
        # Create the index with mapping
        es.indices.create(index=index_name)
        logger.info(f"Created Elasticsearch index: {index_name} with custom mapping")


if __name__ == "__main__":
    # Ensure Elasticsearch is up before proceeding
    logger.info(f"Waiting for Elasticsearch at {ELASTICSEARCH_HOST}:9200...")
    try:
        wait_for_elasticsearch(es)
    except RuntimeError as e:
        logger.error(f"ERROR: {e}")
        raise

    # create Kafka consumer after ES is available
    consumer = KafkaConsumer(NETWORK_LOGS_TOPIC, bootstrap_servers=KAFKA_BROKER)
    es_index_get_or_create(es_index)
    consume_from_kafka()